/*++

Module p_file_path:

    FsFilter1.c

Abstract:

    This is the main module of the FsFilter1 miniFilter driver.

Environment:

    Kernel mode

--*/


///////////////////////////////////////////
/////          FILE INCLUDES          /////
///////////////////////////////////////////
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntddk.h>
#include <stdio.h>
#include <stdlib.h>





///////////////////////////////////////////
/////             MACROS              /////
///////////////////////////////////////////
#define SECUREWORLD_FILENAME_TAG 'SWfn'
#define SECUREWORLD_PRE2POST_TAG 'SWpp'
#define SECUREWORLD_VOLUME_CONTEXT_TAG 'SWvx'
//#define SECUREWORLD_FILE_CONTEXT_TAG 'SWfx' // Not implemented yet. Possible optimization for filename retrieving
#define SECUREWORLD_VOLUME_NAME_TAG 'SWvn'
#define SECUREWORLD_REQUESTOR_NAME_TAG 'SWrn'
#define FILE_POOL_TAG 'SWft'
#define FORBIDDEN_FOLDER_POOL_TAG 'SWpt'
#define AUXILIAR 'SWax'

#define MEMORY 4000

#define MIN_SECTOR_SIZE 0x200

#define MAX_FILEPATH_LENGTH 520     // 260 is enough? The correct way to do it is ask twice the function, first with buffer = 0 and then with the length the function returned (slower)

#define DEBUG_MODE 1                // Affects the PRINT() function. If 0 does not print anything. If 1 debug traces are printed.
#define CHECK_FILENAME 1            // Affects is_special_folder_get_file_name() function. If 0 function always return 0 and null filename pointer. If 1 behaves normally.
#define PROCESS_CREATE_OPERATION 1  // If 0 create operations are not processed. If 1 create operations are processed.
#define PROCESS_READ_OPERATION 1    // If 0 read operations are not processed. If 1 read operations are processed and buffer swapped.
#define PROCESS_WRITE_OPERATION 1   // If 0 write operations are not processed. If 1 write operations are processed and buffer swapped.
//TO DO    #define BUFFER_SWAP 1               // If 0 skips the buffer swap (note this is only valid for same length encription algorithms). If 1 does the buffer swap.

#define PRINT(...) do { if (DEBUG_MODE) DbgPrint(__VA_ARGS__); } while (0)

#define NOOP ((void)0);             // No-operation





///////////////////////////////////////////
/////        TYPE DEFINITIONS         /////
///////////////////////////////////////////

//typedef enum { false, true } bool;    // false = 0,  true = 1

typedef struct _VOLUME_CONTEXT {
    UNICODE_STRING Name;        // Holds the name to display
    ULONG SectorSize;           // Holds sector size for this volume
} VOLUME_CONTEXT, *PVOLUME_CONTEXT;

typedef struct _PRE_2_POST_CONTEXT {
    PVOLUME_CONTEXT VolCtx;     // Volume context to be freed on post-operation (in DPC: can't be got, but can be released)
    PVOID SwappedBuffer;        // Swapped buffer to be freed on post-operation
} PRE_2_POST_CONTEXT, *PPRE_2_POST_CONTEXT;

// Defines the type QUERY_INFO_PROCESS as a pointer to a function that returns NTSTATUS and takes as parameters the provided fields
typedef NTSTATUS(*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
);





///////////////////////////////////////////
/////       FUNCTION PROTOTYPES       /////
///////////////////////////////////////////

NTSTATUS instance_setup(_In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags, _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
void cleanup_volume_context(_In_ PFLT_CONTEXT ctx, _In_ FLT_CONTEXT_TYPE ctx_type);
NTSTATUS mini_unload(FLT_FILTER_UNLOAD_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS mini_pre_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context);
FLT_POSTOP_CALLBACK_STATUS mini_post_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context, FLT_POST_OPERATION_FLAGS flags);

BOOLEAN is_in_folder(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name);
BOOLEAN is_in_folders(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name, WCHAR folders[10][MAX_FILEPATH_LENGTH], const int len);
//BOOLEAN is_in_forbidden_folders(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name);
BOOLEAN is_in_mirrored_folders(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name);
BOOLEAN is_special_folder_get_file_name(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name);
NTSTATUS get_requestor_process_image_path(_In_ PFLT_CALLBACK_DATA data, _Out_ PUNICODE_STRING img_path);
NTSTATUS get_process_image_path(_In_ HANDLE pid, _Out_ PUNICODE_STRING img_path);
//int fill_forbidden_folders(WCHAR* input, WCHAR*** folders, int* len);
//int fill_forbidden_folders(WCHAR* input);
int fill_mirrored_folders(WCHAR* input);
//PUNICODE_STRING convert_path(WCHAR* path);

///////////////////////////////////////////
/////        GLOBAL VARIABLES         /////
///////////////////////////////////////////

PFLT_FILTER filter_handle = NULL;

NPAGED_LOOKASIDE_LIST pre2post_context_list;

QUERY_INFO_PROCESS ZwQueryInformationProcess;


//const WCHAR* p_secure_path = L"\\Device\\HarddiskVolume2\\Users\\Sergio\\Desktop\\Testing\\Inside"; // Length = 59 characters
//const WCHAR* p_secure_path = L"\\Device\\HarddiskVolume2\\Users\\Sergio\\Desktop\\Testing\\Inside\\"; // Length = 60 characters
const WCHAR* p_secure_path = L"\\Device\\HarddiskVolume4\\"; // Length = 24 characters
const WCHAR* internal_drives[] = {L"C:"};   // Drives with letter that have been always attached to the machine (not pendriver,external drives, etc.)
const WCHAR* forbidden_folder = L"\\Device\\HarddiskVolume2\\Users\\Tecnalia\\prueba";
//Support for 10 paths max
//int forbidden_folders_len = 0;
//WCHAR forbidden_folders[10][MAX_FILEPATH_LENGTH];

//Support for 10 paths max
int mirrored_folders_len = 0;
WCHAR mirrored_folders[10][MAX_FILEPATH_LENGTH];

//WCHAR** forbidden_folders;

//For checking parental control folders.
//const int parental_control_folders_len = 2;
//const WCHAR* parental_control_folders[2] = {
//    L"\\Device\\HarddiskVolume2\\Users\\Tecnalia\\prueba",
//    L"\\Device\\HarddiskVolume2\\Users\\Tecnalia\\hola"
//};

char result[4000];

//const WCHAR* challenges_file_path= L"\\Device\\HarddiskVolume2\\Users\\Tecnalia\\Challenges.txt";
//BOOLEAN exist_challenges_file = FALSE;

//const WCHAR* config_file_path = L"\\Device\\HarddiskVolume2\\Users\\Tecnalia\\config.txt";
const WCHAR* mirrored_paths = L"\\Device\\HarddiskVolume2\\Users\\Tecnalia\\mirrored_paths.txt";

//BOOLEAN escenario_empresarial = FALSE;

const FLT_OPERATION_REGISTRATION callbacks[] = {
   #if PROCESS_CREATE_OPERATION
    {IRP_MJ_CREATE, 0, mini_pre_create, mini_post_create},
   #endif

    //{IRP_MJ_SET_INFORMATION, 0, mini_pre_set_information, NULL},

    {IRP_MJ_OPERATION_END}
};

// Context definitions we currently care about. The system will create a lookAside list for the volume context because an explicit size of the context is specified.
const FLT_CONTEXT_REGISTRATION contexts[] = {
    { FLT_VOLUME_CONTEXT, 0, cleanup_volume_context, sizeof(VOLUME_CONTEXT), SECUREWORLD_VOLUME_CONTEXT_TAG },
    //{ FLT_FILE_CONTEXT, 0, cleanup_file_context, sizeof(FILE_CONTEXT), SECUREWORLD_FILE_CONTEXT_TAG },         // Not implemented yet. Possible optimization for filename retrieving
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION filter_registration = {
    sizeof(FLT_REGISTRATION),       // Size
    FLT_REGISTRATION_VERSION,       // Version
    0,                              // Flags
    contexts,                       // Context
    callbacks,                      // Calbacks
    mini_unload,                    // Unload
    instance_setup,                 // InstanceSetup
    NULL,                           // InstanceQueryTeardown
    NULL,                           // InstanceTeardownStart
    NULL,                           // InstanceTeardownComplete
    NULL,                           // GenerateFileName
    NULL,                           // GenerateDestinationFileName
    NULL                            // NormalizeNameComponent
};





///////////////////////////////////////////
/////    FUNCTION IMPLEMENTATIONS     /////
///////////////////////////////////////////

/////     MINIFILTER CALLBACKS     /////
/**
* The filter manager calls this routine on the first operation after a new volume is mounted. Checks if the minifilter is allowed to be attached to the volume.
* Tries to attach to all volumes. Tries to get a "DOS" name for the given volume, if it es not posssible, tries with the "NT" name for the volume (which is what happens on network volumes).  If a name is retrieved a volume context will be created with that name.
*
* @param PCFLT_RELATED_OBJECTS flt_objects
*       The callback operation data.
* @param FLT_INSTANCE_SETUP_FLAGS flags
*       Bitmask of flags that indicate why the instance is being attached
* @param DEVICE_TYPE volume_device_type
*       Device type of the file system volume (CD/Disk/Network)
* @param FLT_FILESYSTEM_TYPE volume_filesystem_type
*       File system type of the volume (unknown, RAW, NTFS, etc.)
* 
* @return NTSTATUS
*       STATUS_SUCCESS - Minifilter attaches to the volume
*       STATUS_FLT_DO_NOT_ATTACH - Minifilter does not attach to the volume
*/
NTSTATUS instance_setup(_In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ FLT_INSTANCE_SETUP_FLAGS flags, _In_ DEVICE_TYPE volume_device_type, _In_ FLT_FILESYSTEM_TYPE volume_filesystem_type)
{
    PDEVICE_OBJECT dev_obj = NULL;
    PVOLUME_CONTEXT ctx = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ret_len;
    PUNICODE_STRING working_name;
    USHORT size;
    UCHAR vol_prop_buffer[sizeof(FLT_VOLUME_PROPERTIES) + 512];
    PFLT_VOLUME_PROPERTIES vol_prop = (PFLT_VOLUME_PROPERTIES)vol_prop_buffer;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(volume_device_type);
    UNREFERENCED_PARAMETER(volume_filesystem_type);

    try
    {
        // Allocate a volume context structure.
        status = FltAllocateContext(flt_objects->Filter, FLT_VOLUME_CONTEXT, sizeof(VOLUME_CONTEXT), NonPagedPool, &ctx);
        if (!NT_SUCCESS(status)) {
            leave;
        }

        // Get volume properties
        status = FltGetVolumeProperties(flt_objects->Volume, vol_prop, sizeof(vol_prop_buffer), &ret_len);
        if (!NT_SUCCESS(status)) {
            leave;
        }

        // Save the sector size in the context for later use
        FLT_ASSERT((vol_prop->SectorSize == 0) || (vol_prop->SectorSize >= MIN_SECTOR_SIZE));
        ctx->SectorSize = max(vol_prop->SectorSize, MIN_SECTOR_SIZE);

        // Init the buffer field (which may be allocated later).
        ctx->Name.Buffer = NULL;

        // Get the storage device object we want a name for.
        status = FltGetDiskDeviceObject(flt_objects->Volume, &dev_obj);
        if (NT_SUCCESS(status)) {
            // Try to get the DOS name. If it succeeds we will have an allocated name buffer. If not, it will be NULL
            status = IoVolumeDeviceToDosName(dev_obj, &ctx->Name);
        }

        // If we could not get a DOS name, get the NT name.
        if (!NT_SUCCESS(status)) {
            FLT_ASSERT(ctx->Name.Buffer == NULL);

            // Figure out which name to use from the properties
            if (vol_prop->RealDeviceName.Length > 0) {
                working_name = &vol_prop->RealDeviceName;
            }
            else if (vol_prop->FileSystemDeviceName.Length > 0) {
                working_name = &vol_prop->FileSystemDeviceName;
            }
            else {
                // No name, don't save the context
                status = STATUS_FLT_DO_NOT_ATTACH;
                leave;
            }

            // Get size of buffer to allocate. This is the length of the string plus room for a trailing colon.
            size = working_name->Length + sizeof(WCHAR);

            // Now allocate a buffer to hold this name
#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "ctx->Name.Buffer will not be leaked because it is freed in cleanup_volume_context")
            ctx->Name.Buffer = ExAllocatePoolWithTag(NonPagedPool, size, SECUREWORLD_VOLUME_NAME_TAG);
            if (ctx->Name.Buffer == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                leave;
            }

            // Init the rest of the fields
            ctx->Name.Length = 0;
            ctx->Name.MaximumLength = size;

            // Copy the name in, and add a colon (just for visual purpose)
            RtlCopyUnicodeString(&ctx->Name, working_name);
            RtlAppendUnicodeToString(&ctx->Name, L":");
        }

        // Set the context (already defined is OK)
        status = FltSetVolumeContext(flt_objects->Volume, FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx, NULL);
        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
            status = STATUS_SUCCESS;
        }

        /////////////////////////////////////////////
        // If volume is not letter "T:" do not attach
        //SW: InstanceSetup:     Real SectSize=0x0000, Used SectSize=0x0200, Name="\Device\Mup:"
        //SW: InstanceSetup:     Real SectSize=0x0200, Used SectSize=0x0200, Name="C:"
        //SW: InstanceSetup:     Real SectSize=0x0200, Used SectSize=0x0200, Name="\\?\Volume{55679090-0000-0000-0000-100000000000}"
        //SW: InstanceSetup:     Real SectSize=0x0200, Used SectSize=0x0200, Name="\\?\Volume{55679090-0000-0000-0000-d05f0c000000}"
        //SW: InstanceSetup:     Real SectSize=0x0200, Used SectSize=0x0200, Name="K:"
        //--------------------------------------------------------------------------------
        // K:               \\?\Volume{820c6478-0000-0000-0000-100000000000}\
        // C:               \\?\Volume{55679090-0000-0000-0000-300300000000}\
        // System reserved  \\?\Volume{55679090-0000-0000-0000-100000000000}\
        // Recovery         \\?\Volume{55679090-0000-0000-0000-d05f0c000000}\
        // \Device\Mup: (Multiple UNC Provider) Kernel-mode component that uses UNC names to channel remote file system accesses to a network redirector (UNC provider) cappable of handling them.
        /*
        //If volume is not T:
        if (RtlCompareUnicodeString(&ctx->Name, L"T:", FALSE))
        {
            if (wcscmp(ctx->Name.Buffer, L"K:") == 0)
            {
                status = STATUS_SUCCESS;
                PRINT("SW: InstanceSetup:       K:      -->  Attached");
            }
            else {
                status = STATUS_FLT_DO_NOT_ATTACH;
                PRINT("SW: InstanceSetup:       Not K:  -->  Not attached");
            }

            PRINT("SW: InstanceSetup:   VOLUME Name = \"%wZ\", Len=%hu, MaxLen=%hu\n", &ctx->Name, ctx->Name.Length, ctx->Name.MaximumLength);
            // By default no not attach
            status = STATUS_FLT_DO_NOT_ATTACH;
        }
        */
        /*
        // Check if name length is a letter plus colon (2 wide characters = 4 Bytes)
        if (ctx->Name.Length == 4)
        {
            // Attach by default if it is a letter drive
            status = STATUS_SUCCESS;

            // Check if it is internal drive, if it is, do not attach
            int internal_drives_length = sizeof internal_drives / sizeof *internal_drives;
            for (size_t i = 0; i < internal_drives_length; i++)
            {
                if (wcscmp(ctx->Name.Buffer, internal_drives[i]) == 0)
                {
                    status = STATUS_FLT_DO_NOT_ATTACH;
                }
            }
        }
        */
        // Check if name length is a letter plus colon (2 wide characters = 4 Bytes)
        if (ctx->Name.Length == 4)
        {
            // No attach by default if it is a letter drive
            status = STATUS_FLT_DO_NOT_ATTACH;

            // Check if it is internal drive, if it is, do attach
            int internal_drives_length = sizeof internal_drives / sizeof * internal_drives;
            for (size_t i = 0; i < internal_drives_length; i++)
            {
                if (wcscmp(ctx->Name.Buffer, internal_drives[i]) == 0)
                {
                    status = STATUS_SUCCESS;
                }
            }
        }


        PRINT("SW: InstanceSetup:   Attached=%s, Name=\"%wZ\", Real SectSize=0x%04x, Used SectSize=0x%04x\n", (status == STATUS_SUCCESS ? "Yes" : "No "), &ctx->Name, vol_prop->SectorSize, ctx->SectorSize);

    }
    finally {

        // Always release the context. If the set failed, it will free the context. If not, it will remove the reference added by the set.
        // Note that the name buffer in the ctx will get freed by the context cleanup routine.
        if (ctx) {
            FltReleaseContext(ctx);
        }

        // Remove the reference added to the device object by FltGetDiskDeviceObject
        if (dev_obj) {
            ObDereferenceObject(dev_obj);
        }
    }

    return status;
}

/**
* Frees the name buffer associated to the volume context
*
* @param PFLT_CONTEXT ctx
*       The context being freed
* @param FLT_CONTEXT_TYPE ctx_type
*       The context type.
*/
VOID cleanup_volume_context(_In_ PFLT_CONTEXT ctx, _In_ FLT_CONTEXT_TYPE ctx_type) {
    PVOLUME_CONTEXT vol_ctx = ctx;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ctx_type);

    FLT_ASSERT(ctx_type == FLT_VOLUME_CONTEXT);

    if (vol_ctx->Name.Buffer != NULL) {
        ExFreePool(vol_ctx->Name.Buffer);
        vol_ctx->Name.Buffer = NULL;
    }
}

NTSTATUS mini_unload(FLT_FILTER_UNLOAD_FLAGS flags) {
    UNREFERENCED_PARAMETER(flags);
    PRINT("SW: Driver unload \r\n");
    FltUnregisterFilter(filter_handle);

    // Delete lookaside list for pre2post
    ExDeleteNPagedLookasideList(&pre2post_context_list);
    return STATUS_SUCCESS;
};

FLT_PREOP_CALLBACK_STATUS mini_pre_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context) {
    UNREFERENCED_PARAMETER(completion_context);
    UNICODE_STRING img_path;
    NTSTATUS status = STATUS_SUCCESS;
    if (NT_SUCCESS(get_requestor_process_image_path(data, &img_path)) && img_path.Length > 0) {
        //PRINT("SW: PreCreate from %wZ", img_path);
        ExFreePoolWithTag(img_path.Buffer, SECUREWORLD_REQUESTOR_NAME_TAG);
    }
    else {
        //PRINT("SW: PreCreate from ???");
    }

    WCHAR* p_file_name = NULL;
    if (is_special_folder_get_file_name(data, &p_file_name)) {
        if (p_file_name) {
            //PRINT("SW: PreCreate in special folder           (%ws)\r\n", p_file_name);
            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
    }
    else {
        if (p_file_name) {
            //PRINT("SW: PreCreate NOT in special folder       (%ws)\r\n", p_file_name);
            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
    }

    //Read mirrored_folders file
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    //PVOID result;
    //result = ExAllocatePoolWithTag(NonPagedPool, MEMORY, FILE_POOL_TAG); //OK
    //if (result)
    //{
        PVOID fileObject;
        UNICODE_STRING myUnicodeStr;
        RtlInitUnicodeString(&myUnicodeStr, mirrored_paths);
        InitializeObjectAttributes(&objectAttributes,
            &myUnicodeStr,
            OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
            NULL,
            NULL);
        IO_STATUS_BLOCK ioStatus;
        status = FltCreateFile(flt_objects->Filter, flt_objects->Instance, &fileHandle, GENERIC_READ,
            &objectAttributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SEQUENTIAL_ONLY,
            NULL, 0, 0);
        if (NT_SUCCESS(status))
        {
            ObReferenceObjectByHandle(fileHandle, GENERIC_READ, NULL, KernelMode,
                &fileObject,
                NULL);
            ULONG bytes_read;
            LARGE_INTEGER offset;
            offset.QuadPart = 0;
            bytes_read = 0;

            //PRINT("File object       (%ws)\r\n", (((PFILE_OBJECT)(fileObject))->FileName).Buffer); //OK
            FltReadFile(flt_objects->Instance, (PFILE_OBJECT)fileObject, &offset, MEMORY, result,
                FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
                &bytes_read, NULL, NULL); //OK
            //PRINT("Content       (%.*s)\r\n",bytes_read, (char*)result);
            FltClose(fileHandle);
            ObDereferenceObject(fileObject);
            WCHAR wText[4000];

            mbstowcs(wText, (char*)result, bytes_read);
            wText[bytes_read] = L'\0';
            //PRINT("Antes de llamar a la funcion %ws", wText);
            //PRINT("Size antes de llamar a la funcion %d", (int)size);
            //int out = fill_forbidden_folders(wText, &forbidden_folders, &forbidden_folders_len);
            int out = fill_mirrored_folders(wText);/*
            for (int i = 0; i < 10; i++)
            {
                PRINT("Forbidden_folders   %d    (%ws)\n", i,forbidden_folders[i]);
            }*/
            if (is_in_mirrored_folders(data, &p_file_name))
            {

                    DbgPrint("[CUSTOM] INTERCEPTING OPERATION");

                    status = STATUS_ACCESS_DENIED;
                    data->IoStatus.Status = status;
                    data->IoStatus.Information = 0;
                    return FLT_PREOP_COMPLETE;
            }
        }
        //ExFreePoolWithTag(result, FILE_POOL_TAG);
    //}
    
    return FLT_PREOP_SUCCESS_NO_CALLBACK; // FLT_PREOP_SUCCESS_WITH_CALLBACK;
    
};

FLT_POSTOP_CALLBACK_STATUS mini_post_create(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context, FLT_POST_OPERATION_FLAGS flags) {
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(flt_objects);
    UNREFERENCED_PARAMETER(completion_context);
    WCHAR* p_file_name = NULL;
    //NTSTATUS status = STATUS_SUCCESS;
    if (is_special_folder_get_file_name(data, &p_file_name)) {
        if (p_file_name) {
            PRINT("SW: PostCreate in special folder          (%ws)\r\n", p_file_name);

            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
        }
    }

    /** DUPLICATED: IT IS ENOUGH TO BLOCK IT IN MINI_PRE FUNCTION
    if (is_in_folder(data, &p_file_name))
    {
        //if (get_requestor_process_image_path(data, NULL) != STATUS_INSUFFICIENT_RESOURCES)
        //{
            DbgPrint("[CUSTOM] INTERCEPTING OPERATION");

            status = STATUS_ACCESS_DENIED;
            data->IoStatus.Status = status;
            data->IoStatus.Information = 0;
            return FLT_POSTOP_FINISHED_PROCESSING;
        //}
    }
    */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
};

FLT_PREOP_CALLBACK_STATUS mini_pre_set_information(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS flt_objects, PVOID* completion_context) {
    UNREFERENCED_PARAMETER(completion_context);
    UNREFERENCED_PARAMETER(flt_objects);
    WCHAR *p_file_name = NULL;
    if (is_special_folder_get_file_name(data, &p_file_name)) {
        if (p_file_name) {
            PRINT("SW: PreSetInformtion in special folder    (%ws)\r\n", p_file_name);

            ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);
            p_file_name = NULL;
            //return FLT_PREOP_SUCCESS_WITH_CALLBACK; // Operation continues processing and will call the post filter
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK; // Operation continues processing but will not call the post filter
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    PRINT("SW: Driver entry\r\n");

    // Initialize look aside list for pre2post
    ExInitializeNPagedLookasideList(&pre2post_context_list, NULL, NULL, 0, sizeof(PRE_2_POST_CONTEXT), SECUREWORLD_PRE2POST_TAG, 0);

    status = FltRegisterFilter(DriverObject, &filter_registration, &filter_handle);
    if (NT_SUCCESS(status)) {
        PRINT("SW: Driver entry register success\r\n");
        
        status = FltStartFiltering(filter_handle);
        if (!NT_SUCCESS(status)) {
            PRINT("SW: Driver entry start filtering success\r\n");
            FltUnregisterFilter(filter_handle);
        }
    }

    return status;
}



/////     CUSTOM FUNCTIONS     /////


/**
* Checks if file is in folder.
*
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param WCHAR **pp_file_name
*       Empty pointer used to output the name if the function returns TRUE.
*       May be NULL if allocation did not succeed.
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);".
*
* @return BOOLEAN
*       If file is in folder.
*/
BOOLEAN is_in_folder(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name) {
    if (!CHECK_FILENAME) {
        *pp_file_name = NULL;
        return TRUE;
    }

    PFLT_FILE_NAME_INFORMATION file_name_info;
    NTSTATUS status;
    WCHAR p_file_path[MAX_FILEPATH_LENGTH] = { 0 };
    WCHAR* p_path_match = NULL;
    BOOLEAN ret_value = FALSE;

    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &file_name_info);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(file_name_info);
        if (NT_SUCCESS(status)) {
            if (file_name_info->Name.MaximumLength < MAX_FILEPATH_LENGTH) {
                RtlCopyMemory(p_file_path, file_name_info->Name.Buffer, file_name_info->Name.MaximumLength);

                p_path_match = wcsstr(p_file_path, forbidden_folder);
                if (p_path_match != NULL && p_path_match == p_file_path) {
                    ret_value = TRUE;   // Match

                    *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                    //WCHAR pp_file_name[MAX_FILEPATH_LENGTH];

                    if (*pp_file_name) {
                        const size_t forbidden_folder_len = wcslen(forbidden_folder);
                        size_t file_name_len = wcslen(p_file_path) - forbidden_folder_len;

                        wcsncpy(*pp_file_name, &p_file_path[forbidden_folder_len], file_name_len);
                        (*pp_file_name)[file_name_len] = L'\0';

                        //PRINT("SW: FilePath: %ws - Length: %zu \r\n", p_file_path, wcslen(p_file_path));
                        //PRINT("SW: File name: %ws - Length: %zu \r\n", *pp_file_name, wcslen(*pp_file_name));
                    }
                }
                else {
                    ret_value = FALSE;  // NO match

                    *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                    if (*pp_file_name) {
                        size_t file_name_len = wcslen(p_file_path);

                        wcsncpy(*pp_file_name, p_file_path, file_name_len);
                        (*pp_file_name)[file_name_len] = L'\0';
                    }
                } // Check filename matches secure path
                FltReleaseFileNameInformation(file_name_info);
                return ret_value;
            }// length >260  buffer not big enough
        }
        else {// Could not parse
            PRINT("SW: ERROR retrieving filename.");
        }
        FltReleaseFileNameInformation(file_name_info);
    }// Could not get
    *pp_file_name = NULL;
    return ret_value;
}


/**
* Checks if file is in the list of forbidden folders.
*
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param WCHAR **pp_file_name
*       Empty pointer used to output the name if the function returns TRUE.
*       May be NULL if allocation did not succeed.
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);".
*
* @return BOOLEAN
*       If file is in folder.
*/
BOOLEAN is_in_folders(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name, WCHAR folders[10][MAX_FILEPATH_LENGTH], const int len) {
    if (!CHECK_FILENAME) {
        *pp_file_name = NULL;
        return TRUE;
    }

    PFLT_FILE_NAME_INFORMATION file_name_info;
    NTSTATUS status;
    WCHAR p_file_path[MAX_FILEPATH_LENGTH] = { 0 };
    WCHAR* p_path_match = NULL;
    BOOLEAN ret_value = FALSE;
    size_t folder_len;
    size_t file_name_len;

    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &file_name_info);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(file_name_info);
        if (NT_SUCCESS(status)) {
            if (file_name_info->Name.MaximumLength < MAX_FILEPATH_LENGTH) {
                RtlCopyMemory(p_file_path, file_name_info->Name.Buffer, file_name_info->Name.MaximumLength);
                int i = 0;
                while (i < len && ret_value==FALSE)
                {
                    p_path_match = wcsstr(p_file_path, folders[i]);
                    if (p_path_match != NULL && p_path_match == p_file_path) {
                        ret_value = TRUE;   // Match

                        *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                        //WCHAR pp_file_name[MAX_FILEPATH_LENGTH];

                        if (*pp_file_name) {
                            folder_len = wcslen(folders[i]);
                            file_name_len = wcslen(p_file_path) - folder_len;

                            wcsncpy(*pp_file_name, &p_file_path[folder_len], file_name_len);
                            (*pp_file_name)[file_name_len] = L'\0';

                            //PRINT("SW: FilePath: %ws - Length: %zu \r\n", p_file_path, wcslen(p_file_path));
                            //PRINT("SW: File name: %ws - Length: %zu \r\n", *pp_file_name, wcslen(*pp_file_name));
                        }
                    }
                    else {
                        ret_value = FALSE;  // NO match

                        *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                        if (*pp_file_name) {
                            file_name_len = wcslen(p_file_path);

                            wcsncpy(*pp_file_name, p_file_path, file_name_len);
                            (*pp_file_name)[file_name_len] = L'\0';
                        }
                    }
                    i++;
                }
                FltReleaseFileNameInformation(file_name_info);
                return ret_value;
            }
        }
        else {// Could not parse
            PRINT("SW: ERROR retrieving filename.");
        }
        FltReleaseFileNameInformation(file_name_info);
    }// Could not get
    *pp_file_name = NULL;
    return ret_value;
}

BOOLEAN is_in_mirrored_folders(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR** pp_file_name) {
    if (!CHECK_FILENAME) {
        *pp_file_name = NULL;
        return TRUE;
    }

    PFLT_FILE_NAME_INFORMATION file_name_info;
    NTSTATUS status;
    WCHAR p_file_path[MAX_FILEPATH_LENGTH] = { 0 };
    WCHAR* p_path_match = NULL;
    BOOLEAN ret_value = FALSE;
    size_t folder_len;
    size_t file_name_len;

    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &file_name_info);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(file_name_info);
        if (NT_SUCCESS(status)) {
            if (file_name_info->Name.MaximumLength < MAX_FILEPATH_LENGTH) {
                RtlCopyMemory(p_file_path, file_name_info->Name.Buffer, file_name_info->Name.MaximumLength); //Almacenamos en p_file_path la ruta completa 
                                                                                                             //del fichero que tratamos de acceder
                int i = 0;
                while (i < mirrored_folders_len && ret_value == FALSE) //Para cada ruta prohibida
                {
                    p_path_match = wcsstr(p_file_path, mirrored_folders[i]); //Devolvemos un puntero a la primera aparicion de la ruta prohibida en el path completo al que tratamos de acceder
                    if (p_path_match != NULL && p_path_match == p_file_path) {
                        ret_value = TRUE;   // Si hay Match

                        *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                        //WCHAR pp_file_name[MAX_FILEPATH_LENGTH];

                        if (*pp_file_name) {
                            folder_len = wcslen(mirrored_folders[i]); //Calculamos la longitud de la carpeta prohibida
                            file_name_len = wcslen(p_file_path) - folder_len; //Calculamos la longitud de del nombre del fichero a bloquear (dentro de la ruta prohibida)

                            wcsncpy(*pp_file_name, &p_file_path[folder_len], file_name_len);
                            (*pp_file_name)[file_name_len] = L'\0';

                            //PRINT("SW: FilePath: %ws - Length: %zu \r\n", p_file_path, wcslen(p_file_path));
                            //PRINT("SW: File name: %ws - Length: %zu \r\n", *pp_file_name, wcslen(*pp_file_name));
                        }
                    }
                    else {
                        ret_value = FALSE;  // NO match

                        *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                        if (*pp_file_name) {
                            file_name_len = wcslen(p_file_path);

                            wcsncpy(*pp_file_name, p_file_path, file_name_len);
                            (*pp_file_name)[file_name_len] = L'\0';
                        }
                    }
                    i++;
                }
                FltReleaseFileNameInformation(file_name_info);
                return ret_value;
            }
        }
        else {// Could not parse
            PRINT("SW: ERROR retrieving filename.");
        }
        FltReleaseFileNameInformation(file_name_info);
    }// Could not get
    *pp_file_name = NULL;
    return ret_value;
}



/**
* Checks if the operation is taking place in the secure folder or not.
* 
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param WCHAR **pp_file_name
*       Empty pointer used to output the name if the function returns TRUE.
*       May be NULL if allocation did not succeed.
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_file_name, SECUREWORLD_FILENAME_TAG);".
* 
* @return BOOLEAN
*       If the operation is taking place in the secure folder.
*/
BOOLEAN is_special_folder_get_file_name(_In_ PFLT_CALLBACK_DATA data, _Out_ WCHAR **pp_file_name) {
    if (!CHECK_FILENAME) {
        *pp_file_name = NULL;
        return TRUE;
    }

    PFLT_FILE_NAME_INFORMATION file_name_info;
    NTSTATUS status;
    WCHAR p_file_path[MAX_FILEPATH_LENGTH] = { 0 };
    WCHAR *p_path_match = NULL;
    BOOLEAN ret_value = FALSE;

    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &file_name_info);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(file_name_info);
        if (NT_SUCCESS(status)) {
            if (file_name_info->Name.MaximumLength < MAX_FILEPATH_LENGTH) {
                RtlCopyMemory(p_file_path, file_name_info->Name.Buffer, file_name_info->Name.MaximumLength);

                p_path_match = wcsstr(p_file_path, p_secure_path);
                if (p_path_match!=NULL && p_path_match==p_file_path) {
                    ret_value = TRUE;   // Match

                    *pp_file_name = (WCHAR *)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH *sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                    //WCHAR pp_file_name[MAX_FILEPATH_LENGTH];

                    if (*pp_file_name) {
                        const size_t secure_path_len = wcslen(p_secure_path);
                        size_t file_name_len = wcslen(p_file_path) - secure_path_len;

                        wcsncpy(*pp_file_name, &p_file_path[secure_path_len], file_name_len);
                        (*pp_file_name)[file_name_len] = L'\0';

                        //PRINT("SW: FilePath: %ws - Length: %zu \r\n", p_file_path, wcslen(p_file_path));
                        //PRINT("SW: File name: %ws - Length: %zu \r\n", *pp_file_name, wcslen(*pp_file_name));
                    }
                } else {
                    ret_value = FALSE;  // NO match

                    *pp_file_name = (WCHAR*)ExAllocatePoolWithTag(PagedPool, MAX_FILEPATH_LENGTH * sizeof(WCHAR), (ULONG)SECUREWORLD_FILENAME_TAG);
                    if (*pp_file_name) {
                        size_t file_name_len = wcslen(p_file_path);

                        wcsncpy(*pp_file_name, p_file_path, file_name_len);
                        (*pp_file_name)[file_name_len] = L'\0';
                    }
                } // Check filename matches secure path
                FltReleaseFileNameInformation(file_name_info);
                return ret_value;
            }// length >260  buffer not big enough
        } else {// Could not parse
            PRINT("SW: ERROR retrieving filename.");
        }
        FltReleaseFileNameInformation(file_name_info);
    }// Could not get
    *pp_file_name = NULL;
    return ret_value;
}

/**
* Gets the full image path of the process which pid is passed by parameter
*
* @param PFLT_CALLBACK_DATA data
*       The callback data of the pre/post operation which caller process path wants to be retrieved.
* @param PUNICODE_STRING p_img_path
*       Empty pointer used to output the name if the function returns a valid status.
*       May be NULL if allocation failed (when STATUS_INSUFFICIENT_RESOURCES is returned).
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_img_path->Buffer, SECUREWORLD_REQUESTOR_NAME_TAG);".
*
* @return NTSTATUS
*       A status corresponding to the success or failure of the operation.
*/
NTSTATUS get_requestor_process_image_path(_In_ PFLT_CALLBACK_DATA data, _Out_ PUNICODE_STRING p_img_path) {
    NTSTATUS status;
    PEPROCESS obj_process = NULL;
    HANDLE proc_handle;

    obj_process = IoThreadToProcess(data->Thread);

    proc_handle = PsGetProcessId(obj_process);

    p_img_path->Length = 0;
    p_img_path->MaximumLength = MAX_FILEPATH_LENGTH;
    p_img_path->Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, MAX_FILEPATH_LENGTH, SECUREWORLD_REQUESTOR_NAME_TAG);
    if (p_img_path->Buffer) {
        status = get_process_image_path(proc_handle, p_img_path);
        if (NT_SUCCESS(status)) {
            NOOP
            //PRINT("SW: ---> requestor: %wZ", p_img_path);
        } else{
            ExFreePoolWithTag(p_img_path->Buffer, SECUREWORLD_REQUESTOR_NAME_TAG);
        }
    } else {
        status = STATUS_INSUFFICIENT_RESOURCES;
        p_img_path->Buffer = NULL;
    }

    return status;
}

/**
* Gets the full image path of the process which pid is passed by parameter
* Copied from: https://stackoverflow.com/a/40507407/7505211
*
* @param HANDLE pid
*       A handle (process ID) of the process which path wants to be retrieved.
* @param PUNICODE_STRING p_img_path
*       Empty pointer used to output the name if the function returns a valid status.
*       May be NULL if allocation did not succeed.
*       Memory is allocated inside, remember to free it with "ExFreePoolWithTag(p_img_path->Buffer, SECUREWORLD_REQUESTOR_NAME_TAG);".
*
* @return NTSTATUS
*       A status corresponding to the success or failure of the operation.
*/
NTSTATUS get_process_image_path(_In_ HANDLE pid, _Out_ PUNICODE_STRING p_img_path) {
    NTSTATUS status;
    ULONG returned_length;
    ULONG buffer_length;
    HANDLE h_process = NULL;
    PVOID buffer;
    PEPROCESS p_eprocess;
    PUNICODE_STRING p_tmp_img_path;

    PAGED_CODE(); // This eliminates the possibility of the IDLE Thread/Process

    status = PsLookupProcessByProcessId(pid, &p_eprocess);

    if (NT_SUCCESS(status)) {
        status = ObOpenObjectByPointer(p_eprocess, 0, NULL, 0, 0, KernelMode, &h_process);
        if (NT_SUCCESS(status)) {
        } else {
            PRINT("SW: ObOpenObjectByPointer Failed: %08x\n", status);
        }
        ObDereferenceObject(p_eprocess);
    } else {
        PRINT("SW: PsLookupProcessByProcessId Failed: %08x\n", status);
    }

    if (NULL == ZwQueryInformationProcess) {
        UNICODE_STRING routine_name;
        RtlInitUnicodeString(&routine_name, L"ZwQueryInformationProcess");

        ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routine_name);

        if (NULL == ZwQueryInformationProcess) {
            PRINT("SW: Cannot resolve ZwQueryInformationProcess\n");
        }
    }

    // Query the actual size of the process path
    status = ZwQueryInformationProcess(h_process, ProcessImageFileName, NULL, 0, &returned_length);

    if (STATUS_INFO_LENGTH_MISMATCH != status) {
        return status;
    }

    // Check if there is enough space to store the actual process path when it is found. If not return an error with the required size
    buffer_length = returned_length - sizeof(UNICODE_STRING);
    if (p_img_path->MaximumLength < buffer_length) {
        p_img_path->MaximumLength = (USHORT)buffer_length;
        return STATUS_BUFFER_OVERFLOW;
    }

    // Allocate a temporary buffer to store the path name
    buffer = ExAllocatePoolWithTag(NonPagedPool, returned_length, SECUREWORLD_REQUESTOR_NAME_TAG);

    if (NULL == buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Retrieve the process path from the handle to the process
    status = ZwQueryInformationProcess(h_process, ProcessImageFileName, buffer, returned_length, &returned_length);

    if (NT_SUCCESS(status)) {
        // Copy the path name
        p_tmp_img_path = (PUNICODE_STRING)buffer;
        RtlCopyUnicodeString(p_img_path, p_tmp_img_path);
    }

    // Free the temp buffer which stored the path
    ExFreePoolWithTag(buffer, SECUREWORLD_REQUESTOR_NAME_TAG);

    return status;
}


int fill_mirrored_folders(WCHAR* input)
{
    int i = 0;
    size_t len = 0;
    size_t input_len = wcslen(input);
    mirrored_folders_len = 0;
    WCHAR* aux = input;
    while (i < (int)input_len)
    {
        len++;
        //PRINT(" Letra: %lc", input[i]);
        if (input[i] == L'\n') //Si encuentra un ;
        {
            PRINT("Encuentra el caracter %lc", input[i]);
            PRINT("Input    (%ws)\r\n", input); //Ruta a guardar
            wcsncpy(mirrored_folders[mirrored_folders_len], aux, len - 1);  //Copiamos todo menos el ;
            mirrored_folders[mirrored_folders_len][len - 2] = L'\0'; //Le ponemos un /0 al final porque wcsncpy no lo hace
            //PRINT("Carpeta prohibida numero %d,   (%ws)\r\n", forbidden_folders_len, forbidden_folders[forbidden_folders_len]); //Carpeta prohibida
            PRINT("Forbidden_folders   0    (%ws)\n", mirrored_folders[0]);
            PRINT("Forbidden_folders   1    (%ws)\n", mirrored_folders[1]);
            mirrored_folders_len++;
            if (i + 1 < (int)input_len) //Si no es el ultimo caracter
            {
                aux = input + i + 1; //Actualizamos Aux para que apunte a la siguiente ruta, solo si no se ha llegado al final
                //PRINT("QUEDA OTRA RUTA");
            }
            len = 0;
        }
        i++;
    }
    //aux = NULL;
    return 0;
}



/////     BUFFER SWAP FUNCTIONS     /////

/**
* Performs the buffer swap before the reading operation
* Note that it handles all errors by simply not doing the buffer swap.
*
* @param PFLT_CALLBACK_DATA data
*       The callback operation data.
* @param PCFLT_RELATED_OBJECTS flt_objects
*       Pointer to the FLT_RELATED_OBJECTS data structure containing opaque handles to this filter, instance, its associated volume and file object.
* @param PVOID* completion_context
*       Pointer that allows information to be passed from pre to post operation
*
* @return FLT_PREOP_CALLBACK_STATUS
*       FLT_PREOP_SUCCESS_WITH_CALLBACK - mark success and demand post operation callback
*       FLT_PREOP_SUCCESS_NO_CALLBACK - mark success and do not perform post operation callback
*       FLT_PREOP_COMPLETE - marks the request as completed so the operation is not performed
*/



//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////EOF//////

// From here onwards everything is commented out. Only for testing purposes
/*


/////     HOW TO PRINT DIFFERENT TYPES     /////

PUNICODE_STRING         %wZ
ULONG                   %d
char                    %c
USHORT                  %hu

http://www.cplusplus.com/reference/cstdio/printf/



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <wchar.h>

const wchar_t * p_secure_path = L"\\Device\\HarddiskVolume2\\Users\\Sergio\\Desktop\\Testing\\Inside\\"; // Len: 60
const wchar_t * p_file_path = L"\\Device\\HarddiskVolume2\\Users\\Sergio\\Desktop\\Testing\\Inside\\fichero.txt"; // Len: ?
wchar_t * p_path_match = NULL;

int main()
{
    p_path_match = wcsstr(p_file_path, p_secure_path);
    wprintf (L"p1 %p \r\np2: %p \r\n", p_file_path, p_path_match);
    if (p_file_path==p_path_match) wprintf(L"IGUALES \r\n");

    int SecureFolderPathLen = (int)wcslen(p_secure_path);
    wprintf (L"Secure path: %ls \r\n", p_secure_path);
    wprintf (L"Length: %d \r\n", SecureFolderPathLen);

    int FilePathLen = (int)wcslen(p_file_path);
    wprintf (L"File path: %ls \r\n", p_file_path);
    wprintf (L"Length: %d \r\n", FilePathLen);

    wchar_t pp_file_name[260];
    int file_name_len = wcslen(p_file_path) - wcslen(p_secure_path);
    wcsncpy( pp_file_name, &p_file_path[SecureFolderPathLen], (size_t)file_name_len+1 );

    wprintf (L"File name: %ls \r\n", pp_file_name);
    wprintf (L"Length: %d \r\n", (int)wcslen(pp_file_name));
    wprintf (L"Length: %d \r\n", file_name_len);

    return 0;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


///// THIS WORKS to know the process which requested the operation /////

PEPROCESS objCurProcess = NULL;
HANDLE hProcess;
UNICODE_STRING fullPath;
NTSTATUS status;

objCurProcess = IoThreadToProcess(data->Thread);

hProcess = PsGetProcessId(objCurProcess);

fullPath.Length = 0;
fullPath.MaximumLength = 520;
fullPath.Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, 520, 'uUT1');
if (fullPath.Buffer) {
    status = get_process_image_path(hProcess, &fullPath);
    DbgPrint("SW: PreCreate requestor status: %d", (int)status);

    if (NT_SUCCESS(status)) {
        DbgPrint("SW: PreCreate from: %wZ", fullPath);
    }
    ExFreePoolWithTag(fullPath.Buffer, 'uUT1');
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



*/

/*Not working
PUNICODE_STRING convert_path(WCHAR* path)
{
    NTSTATUS ntStatus;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    PUNICODE_STRING myUnicodeStr=NULL;
    PFILE_OBJECT  Object = NULL;
    POBJECT_NAME_INFORMATION dosNameInfo = NULL;
    RtlInitUnicodeString(myUnicodeStr, path);
    InitializeObjectAttributes(&objectAttributes,
        myUnicodeStr,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    ntStatus=ZwOpenSymbolicLinkObject(&fileHandle, GENERIC_READ, &objectAttributes);
    if (ntStatus)
    {
        ntStatus=ZwQuerySymbolicLinkObject(fileHandle,myUnicodeStr, NULL);
        if (ntStatus)
        {
            ntStatus = ObReferenceObjectByHandle(
                fileHandle,
                GENERIC_READ,
                NULL,
                KernelMode,
                (PVOID*)Object,
                NULL);
            if (ntStatus)
            {
                ntStatus = IoQueryFileDosDeviceName(Object, &dosNameInfo);
                ExFreePool(Object);
            }
        }
    }
    return &(dosNameInfo->Name);
}
*/




















/*
/////  GLOBAL VARS  /////

struct LetterDeviceMap* letter_device_table;

#define NUM_LETTERS 26

#define MAX_PATH 520


struct LetterDeviceMap {

    WCHAR letter;

    WCHAR device[MAX_PATH];

};
*/

/////  FUNCTIONS  /////

/**
* Fills the letter_device_table global variable.
*/
/*
void initLetterDeviceMapping() {
    unsigned int logical_drives_mask = 0;
    int count = 0;
    WCHAR tmp_str[3] = L" :";
    int index = 0;

    logical_drives_mask = GetLogicalDrives();

    //printf("logical_drives_mask (in hex): %X\n", logical_drives_mask);
    for (size_t i = 0; i < NUM_LETTERS; i++) {
        if (logical_drives_mask & (1 << i)) {
            count++;
        }
    }

    letter_device_table = malloc(count * sizeof(struct LetterDeviceMap));
    if (letter_device_table) {
        index = 0;
        for (size_t j = 0; j < NUM_LETTERS; j++) {
            if (logical_drives_mask & (1 << j)) {
#pragma warning(suppress: 6386)
                letter_device_table[index].letter = (WCHAR)('A' + j);
#pragma warning(suppress: 6385)
                tmp_str[0] = letter_device_table[index].letter;
                if (QueryDosDeviceW(tmp_str, letter_device_table[index].device, MAX_PATH) == 0) {
                    fprintf(stderr, "ERROR: device path translation of letter %wc: is longer than %d.\n", letter_device_table[index].letter, MAX_PATH);
                }
                index++;
            }
        }
    }
    else {
        fprintf(stderr, "ERROR: failed to allocate necessary memory.\n");
        exit(1);
    }

    // print table
    PRINT("\nletter_device_table:\n");
    for (size_t i = 0; i < count; i++) {
        PRINT("%wc: --> %ws\n", letter_device_table[i].letter, letter_device_table[i].device);
    }
}


void clearPathSlashes(WCHAR* path) {
    WCHAR* tmp_str = NULL;

    // Clear possible forward slashes into backward slashes
    //PRINT("Clearing slashes in '%ws'\n", path);
    tmp_str = wcschr(path, L'/');
    while (tmp_str != NULL) {
        *tmp_str = L'\\';
        tmp_str = wcschr(path, L'/');
    }
}


int fromDeviceToLetter(WCHAR** full_path) {
    WCHAR* tmp_str = NULL;
    WCHAR* match_ptr;
    WCHAR* new_full_path;
    size_t initial_len;
    size_t device_len;

    // Clear possible forward slashes into backward slashes
    clearPathSlashes(*full_path);

    // Change Device path for DOS letter path
    //PRINT("Looking for Device path match in '%ws'\n", *full_path);
    initial_len = wcslen(*full_path);
    for (size_t i = 0; i < _msize(letter_device_table) / sizeof(struct LetterDeviceMap); i++) {
        device_len = wcslen(letter_device_table[i].device);
        if (initial_len > device_len) {
            match_ptr = wcsstr(*full_path, letter_device_table[i].device);
            if (match_ptr && match_ptr == *full_path) {
                //PRINT("Match found, allocating %lld * sizeof(WCHAR)\n", (initial_len - device_len + 2 + 1));
                new_full_path = malloc((initial_len - device_len + 2 + 1) * sizeof(WCHAR));					// +2 for "X:" and +1 for null char
                if (new_full_path) {
                    // Fill new full path
                    //PRINT("Allocate success: Fill new full path\n");
                    new_full_path[0] = letter_device_table[i].letter;
#pragma warning(suppress: 6386)
                    new_full_path[1] = L':';
                    wcscpy(&(new_full_path[2]), &((*full_path)[device_len - 1 + 1]));	// -1 because indexes start on 0 and +1 to start on the next slot
                    // Free old full path
                    //PRINT("Allocate success: Free old full path\n");
                    free(*full_path);
                    // Assign new full path
                    //PRINT("Allocate success: Assign new full path\n");
                    *full_path = new_full_path;
                    return 0;
                }
                else {
                    return 2;	// Could not allocate memory
                }
            }
        }
    }

    return 1;	// No matches
}

void formatPath(WCHAR** full_path, _In_ PCFLT_RELATED_OBJECTS flt_objects, _In_ FLT_INSTANCE_SETUP_FLAGS flags, _In_ DEVICE_TYPE volume_device_type, _In_ FLT_FILESYSTEM_TYPE volume_filesystem_type) {
    HANDLE handle = NULL;
    WCHAR* new_full_path = NULL;
    unsigned int result = 0;
    unsigned int attributes_flags = FILE_ATTRIBUTE_NORMAL;

    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatus;

    UNICODE_STRING myUnicodeStr;
    RtlInitUnicodeString(&myUnicodeStr, L"Path en formato normal");
    InitializeObjectAttributes(&objectAttributes,
        &myUnicodeStr,
        OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
        NULL,
        NULL);

    //Comprobar si el dato que buscamos está en objectAttributes.ObjectName
    //PRINT("Function formatPath() starts with '%ws'\n", *full_path);
    if (wcsstr(*full_path, L"Device") != NULL) {	//== &((*full_path)[1])) {
        //PRINT("Starting fromDeviceToLetter() function on '%ws'\n", *full_path);
        fromDeviceToLetter(full_path);
    }

    handle = CreateFileW(*full_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, attributes_flags, NULL);
    FltCreateFile(flt_objects->Filter, flt_objects->Instance, &handle, GENERIC_READ,
        &objectAttributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SEQUENTIAL_ONLY,
        NULL, 0, 0);


    if (handle != INVALID_HANDLE_VALUE && handle != NULL) {
        //Si la información no está en objectAttributes.ObjectName, probar con FltGetDestinationFileNameInformation function
        result = GetFinalPathNameByHandleW(handle, new_full_path, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
        if (result != 0) {
            new_full_path = malloc(result * sizeof(WCHAR));
            if (new_full_path) {
                if (result - 1 == GetFinalPathNameByHandleW(handle, new_full_path, result, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS )) {
                    free(*full_path);
                    *full_path = new_full_path;
                }
                else {
                    free(new_full_path);
                }
            }
        }
        CloseHandle(handle);
    }
}
*/

/*
static int jsoneq(const char* json, jsmntok_t* tok, const char* s) {
if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
    strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
}
return -1;
}
*/
#include <ntddk.h>
///////////////////定义本地结构体//////////////////////////////////////////
struct _SYSTEM_THREADS 
{ 
    LARGE_INTEGER KernelTime; 
    LARGE_INTEGER UserTime; 
    LARGE_INTEGER CreateTime; 
    ULONG WaitTime; 
    PVOID StartAddress; 
    CLIENT_ID ClientIs; 
    KPRIORITY Priority; 
    KPRIORITY BasePriority; 
    ULONG ContextSwitchCount; 
    ULONG ThreadState; 
    KWAIT_REASON WaitReason; 
}; 

typedef struct _SYSTEM_PROCESSES 
{ 
    ULONG NextEntryDelta;
    ULONG ThreadCount; 
    ULONG Reserved[6]; 
    LARGE_INTEGER CreateTime; 
    LARGE_INTEGER UserTime; 
    LARGE_INTEGER KernelTime; 
    UNICODE_STRING ProcessName; 
    KPRIORITY BasePriority; 
    ULONG ProcessId; 
    ULONG InheritedFromProcessId; 
    ULONG HandleCount; 
    ULONG Reserved2[2]; 
    VM_COUNTERS VmCounters; 
    IO_COUNTERS IoCounters; 
    struct _SYSTEM_THREADS Threads[1]; 
}*PSYSTEM_PROCESS, SYSTEM_PROCESS; 


////导出SSDT表
typedef struct _ServiceDescriptorEntry {  
    unsigned int *ServiceTableBase;//System Service Dispatch Table 的基地址。
    unsigned int *ServiceCounterTableBase;//此域用于操作系统的 checked builds
    unsigned int NumberOfServices;//由 ServiceTableBase 描述的服务的数目
    unsigned char *ParamTableBase;//包含每个系统服务参数字节数表的基地址。
}ServiceDescriptorTableEntry, *PServiceDescriptorTableEntry;

typedef struct _KESSDT
{
    PVOID ServiceTableBase;
    PVOID ServiceCounterTableBase;
    unsigned int NumberOfService;
    PVOID ParamTableBase;    
}ServiceDescriptorEntry, *PServiceDescriptorEntry;
 
//通过进程id来获取进程格式
NTSTATUS
PsLookupProcessByProcessId(IN HANDLE ProcessId,
						  OUT PEPROCESS *Process);
HANDLE PsGetProcessId( __in PEPROCESS Process );
UCHAR *PsGetProcessImageFileName(PEPROCESS EProcess);

//dll动态链接库导出
__declspec (dllimport)ServiceDescriptorEntry KeServiceDescriptorTable;

#define QUERYSYSTEMINFORMATIONID 0xAD
#define SystemProcessAndThreadsInformation 5

//对MyNtOpenProcess方法的申明
typedef NTSTATUS(*MYNTOPENPROCESS)(
  OUT PHANDLE             ProcessHandle,
  IN ACCESS_MASK          AccessMask,
  IN POBJECT_ATTRIBUTES   ObjectAttributes,
  IN PCLIENT_ID           ClientId );//定义一个指针函数，用于下面对Old_NtOpenProcess进行强制转换
ULONG Old_NtOpenProcess; //存储原openprocess函数地址
//对MyNtTerminateProcess方法的申明
typedef NTSTATUS(*MYNTTERMINATEPROCESS)(
	IN HANDLE ProcessHandle,
	IN NTSTATUS ExitStatus);//用于对Old_NtTerminateProcess的强制转换
ULONG Old_NtTerminateProcess;//存储原terminateprocess函数地址

////对MyNtOpenProcess方法的实现
NTSTATUS MyNtOpenProcess (
  __out PHANDLE ProcessHandle,
  __in ACCESS_MASK DesiredAccess,
  __in POBJECT_ATTRIBUTES ObjectAttributes,
  __in_opt PCLIENT_ID ClientId
  )
{
    PEPROCESS process; 
	NTSTATUS status;
    char *imageName;  
	
	//找到现在进程的名字，然后和我们要干扰的名字相比，相同直接返回失败
    status = PsLookupProcessByProcessId(ClientId->UniqueProcess, &process);  
	if(NT_SUCCESS(status)){
		////经过174偏移获取正式process名字
		imageName = (char *)((PUCHAR)process + 0x174); 
		////如果名字相同，如果相同就保护该进程
		if (!strcmp(imageName, "notepad.exe")) {  
			KdPrint(("Protect %s(%d)!\n", imageName,ClientId->UniqueProcess));  
			*ProcessHandle=NULL;
			return STATUS_ACCESS_DENIED;  
		}      
	}
    status = ((MYNTOPENPROCESS)Old_NtOpenProcess)(ProcessHandle,
    DesiredAccess,
    ObjectAttributes,
    ClientId);
	if(NT_SUCCESS(status)){
		KdPrint(("OPEN %s",imageName)); 
	}
	return status;
}  
//为了去除SSDT表的只读属性
//关闭页面保护 
void PageProOff()
{
  __asm{
	  cli
      mov  eax,cr0
      and  eax,not 10000h
      mov  cr0,eax
    }
}

////对MyNtTerminateProcess方法的实现
NTSTATUS MyNtTerminateProcess(
    __in_opt HANDLE ProcessHandle,
	__in NTSTATUS ExitStatus)
{
    ULONG uPID;
    NTSTATUS rtStatus;
	NTSTATUS status;
    PCHAR pStrProcName;
    PEPROCESS pEProcess;
    char *strProcName;
	
	//KdPrint(("MyNtTerminateProcess.\n"));  

    //通过进程句柄来获得该进程所对应的 FileObject 对象，由于这里是进程对象，获得的是 EPROCESS 对象
    rtStatus = ObReferenceObjectByHandle(ProcessHandle, 
                FILE_READ_DATA, NULL, KernelMode, &pEProcess, NULL);
    if(!NT_SUCCESS(rtStatus))
    {
        return rtStatus;
    }

	//获得进程名
	uPID = (ULONG)PsGetProcessId(pEProcess);
    status = PsLookupProcessByProcessId(uPID,pEProcess);
	strProcName = (char *)((PUCHAR)pEProcess + 0x174);
   
    
	KdPrint(("TERMINATE %s !", strProcName));
    rtStatus = ((MYNTTERMINATEPROCESS)Old_NtTerminateProcess)(ProcessHandle, ExitStatus);
	
  
    return rtStatus;
}


//为了将SSDT表的只读属性回复，否则就会蓝屏
//打开页面保护 
void PageProOn()
{
  __asm{
    mov  eax,cr0
    or   eax,10000h
    mov  cr0,eax
    sti
  }
}
//对MyNtQuerySystemInformation方法的申明
typedef NTSTATUS (*ZWQUERYSYSTEMINFORMATION)(
    IN ULONG SystemInformationClass, 
    IN PVOID SystemInformation, 
    IN ULONG SystemInformationLength, 
    OUT PULONG ReturnLength);

// 定义一个旧的ZwQuerySystemInformation的旧址用以回复
ZWQUERYSYSTEMINFORMATION OldQuerySystemInformation;

//MyZwQuerySystemInformation方法实现
NTSTATUS MyZwQuerySystemInformation(IN ULONG SystemInformationClass, IN OUT PVOID SystemInformation, 
                                    IN ULONG SystemInformationLength, OUT PULONG ReturnLength)
{
    PSYSTEM_PROCESS systemprocess;
    PSYSTEM_PROCESS prev;
    NTSTATUS status;
    UNICODE_STRING uprocessname;

    if (NULL == OldQuerySystemInformation)
    {
        return STATUS_UNSUCCESSFUL;
    }

    status = OldQuerySystemInformation(SystemInformationClass, SystemInformation,
        SystemInformationLength, ReturnLength);


    if (!NT_SUCCESS(status))
    {
        return status;
    }

    if (SystemProcessAndThreadsInformation != SystemInformationClass)
    {
        return status;
    }

    RtlInitUnicodeString(&uprocessname, L"mspaint.exe");
    systemprocess = (PSYSTEM_PROCESS)SystemInformation;
    prev = systemprocess;

    while(systemprocess->NextEntryDelta)
    {
        if (RtlEqualUnicodeString(&systemprocess->ProcessName, &uprocessname, TRUE))
        {
            //prev->NextEntryDelta = systemprocess + systemprocess->NextEntryDelta;
            prev->NextEntryDelta = prev->NextEntryDelta + systemprocess->NextEntryDelta;
            DbgPrint("Hide mspaint.exe\n");
            break;
        }

        prev = systemprocess;
        systemprocess = (PSYSTEM_PROCESS)((char*)systemprocess + systemprocess->NextEntryDelta);
    }

    return status;
}
//去除OpenProcess方法的钩子
void UnHookOpen()
{
	ULONG OpenAddress;
	ULONG OpenServiceNumber;
	OpenServiceNumber = *(PULONG)((PUCHAR)ZwOpenProcess+1);
    OpenAddress = (ULONG)KeServiceDescriptorTable.ServiceTableBase + OpenServiceNumber*4; 
	
    PageProOff();
	//恢复原来地址
    *(ULONG*)OpenAddress = (ULONG)Old_NtOpenProcess;
    PageProOn();
}
//去除TerminateProcess函数的钩子
void UnHookTerminate()
{
	ULONG TerAddress;
	ULONG TerServiceNumber;
		
	TerServiceNumber = *(PULONG)((PUCHAR)ZwTerminateProcess+1);
    TerAddress = (ULONG)KeServiceDescriptorTable.ServiceTableBase + TerServiceNumber*4;

    PageProOff();
	//恢复原来地址
	*(ULONG*)TerAddress = (ULONG)Old_NtTerminateProcess;
    PageProOn();
}

//解除驱动
NTSTATUS Unload(PDRIVER_OBJECT DriverObject)
{
    ULONG address = (ULONG)((char*)KeServiceDescriptorTable.ServiceTableBase + QUERYSYSTEMINFORMATIONID * 4);
    PageProOff();

    *((ULONG*)address) = (ULONG)OldQuerySystemInformation;

    PageProOn();

	UnHookOpen();
	UnHookTerminate();
	KdPrint(("Driver Unload Success !"));
    
    return STATUS_SUCCESS;
}

//挂载Open驱动
NTSTATUS ssdt_OpenHook()
{
	//获得原来openprocess的地址，换成自己的地址
	//保存原地址
	ULONG OpenAddress;

	ULONG OpenServiceNumber;

	OpenServiceNumber = *(PULONG)((PUCHAR)ZwOpenProcess+1);
    OpenAddress = (ULONG)KeServiceDescriptorTable.ServiceTableBase + OpenServiceNumber*4; 
		
    PageProOff();
  //将原来ssdt中所要hook的函数地址换成我们自己的函数地址
    Old_NtOpenProcess = *(ULONG*)OpenAddress ;
	*(ULONG*)OpenAddress = (ULONG)MyNtOpenProcess;

    PageProOn();
    return STATUS_SUCCESS;
}

//挂载Terminate函数驱动
NTSTATUS ssdt_TerminateHook()
{
	//获得原来terminateprocess的地址，换成自己的地址
	//保存原地址
	ULONG TerAddress;

	ULONG TerServiceNumber;

	TerServiceNumber = *(PULONG)((PUCHAR)ZwTerminateProcess+1);
    TerAddress = (ULONG)KeServiceDescriptorTable.ServiceTableBase + TerServiceNumber*4;

    PageProOff();
    //将原来ssdt中所要hook的函数地址换成我们自己的函数地址
	Old_NtTerminateProcess = *(ULONG*)TerAddress;
	*(ULONG*)TerAddress = (ULONG)MyNtTerminateProcess;
    PageProOn();
    return STATUS_SUCCESS;
}

//挂载Query函数驱动
NTSTATUS ssdt_QueryHook()
{
	//获得原来terminateprocess的地址，换成自己的地址
	//保存原地址
	ULONG QueryAddress;
    QueryAddress = (ULONG)((char*)KeServiceDescriptorTable.ServiceTableBase + QUERYSYSTEMINFORMATIONID * 4);

    PageProOff();
    //将原来ssdt中所要hook的函数地址换成我们自己的函数地址
	OldQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)*((ULONG*)QueryAddress);
	 *((ULONG*)QueryAddress) = (ULONG*)MyZwQuerySystemInformation;
    PageProOn();
    return STATUS_SUCCESS;
}

//驱动加载入口
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    //ULONG address = (ULONG)((char*)KeServiceDescriptorTable.ServiceTableBase + QUERYSYSTEMINFORMATIONID * 4);
    //OldQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)*((ULONG*)address);

	DbgPrint("My Own Hook Driver!");
	ssdt_QueryHook();
	ssdt_OpenHook();
	ssdt_TerminateHook();
    DriverObject->DriverUnload = Unload;
    return STATUS_SUCCESS;
}


/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0628 */
/* at Tue Jan 19 11:14:07 2038
 */
/* Compiler settings for coerced.idl:
    Oicf, W1, Zp8, env=Win64 (32b run), target_arch=AMD64 8.01.0628 
    protocol : all , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __coerced_h_h__
#define __coerced_h_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef DECLSPEC_XFGVIRT
#if defined(_CONTROL_FLOW_GUARD_XFG)
#define DECLSPEC_XFGVIRT(base, func) __declspec(xfg_virtual(base, func))
#else
#define DECLSPEC_XFGVIRT(base, func)
#endif
#endif

/* Forward Declarations */ 

#ifdef __cplusplus
extern "C"{
#endif 


/* interface __MIDL_itf_coerced_0000_0000 */
/* [local] */ 

typedef unsigned short wchar_t;

typedef void *ADCONNECTION_HANDLE;

typedef int BOOL;

typedef int *PBOOL;

typedef int *LPBOOL;

typedef unsigned char BYTE;

typedef unsigned char *PBYTE;

typedef unsigned char *LPBYTE;

typedef BYTE BOOLEAN;

typedef BYTE *PBOOLEAN;

typedef wchar_t WCHAR;

typedef wchar_t *PWCHAR;

typedef WCHAR *BSTR;

typedef unsigned char CHAR;

typedef unsigned char *PCHAR;

typedef double DOUBLE;

typedef unsigned long DWORD;

typedef unsigned long *PDWORD;

typedef unsigned long *LPDWORD;

typedef unsigned int DWORD32;

typedef unsigned __int64 DWORD64;

typedef unsigned __int64 *PDWORD64;

typedef unsigned __int64 ULONGLONG;

typedef ULONGLONG DWORDLONG;

typedef ULONGLONG *PDWORDLONG;

typedef unsigned long error_status_t;

typedef float FLOAT;

typedef unsigned char UCHAR;

typedef unsigned char *PUCHAR;

typedef short SHORT;

typedef void *HANDLE;

typedef DWORD HCALL;

typedef int INT;

typedef int *LPINT;

typedef signed char INT8;

typedef short INT16;

typedef int INT32;

typedef __int64 INT64;

typedef void *LDAP_UDP_HANDLE;

typedef const wchar_t *LMCSTR;

typedef WCHAR *LMSTR;

typedef long LONG;

typedef long *PLONG;

typedef long *LPLONG;

typedef __int64 LONGLONG;

typedef LONG HRESULT;

typedef /* [custom] */ __int3264 LONG_PTR;

typedef /* [custom] */ unsigned __int3264 ULONG_PTR;

typedef int LONG32;

typedef __int64 LONG64;

typedef __int64 *PLONG64;

typedef const unsigned char *LPCSTR;

typedef const void *LPCVOID;

typedef const wchar_t *LPCWSTR;

typedef unsigned char *PSTR;

typedef unsigned char *LPSTR;

typedef wchar_t *LPWSTR;

typedef wchar_t *PWSTR;

typedef DWORD NET_API_STATUS;

typedef long NTSTATUS;

typedef /* [context_handle] */ void *PCONTEXT_HANDLE;

typedef /* [ref] */ PCONTEXT_HANDLE *PPCONTEXT_HANDLE;

typedef unsigned __int64 QWORD;

typedef void *RPC_BINDING_HANDLE;

typedef UCHAR *STRING;

typedef unsigned int UINT;

typedef unsigned char UINT8;

typedef unsigned short UINT16;

typedef unsigned int UINT32;

typedef unsigned __int64 UINT64;

typedef unsigned long ULONG;

typedef unsigned long *PULONG;

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef unsigned int ULONG32;

typedef unsigned __int64 ULONG64;

typedef wchar_t UNICODE;

typedef unsigned short USHORT;

typedef void VOID;

typedef void *PVOID;

typedef void *LPVOID;

typedef unsigned short WORD;

typedef unsigned short *PWORD;

typedef unsigned short *LPWORD;

typedef struct _FILETIME
    {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
    } 	FILETIME;

typedef struct _FILETIME *PFILETIME;

typedef struct _FILETIME *LPFILETIME;

typedef struct _GUID
    {
    unsigned long Data1;
    unsigned short Data2;
    unsigned short Data3;
    byte Data4[ 8 ];
    } 	GUID;

typedef struct _GUID UUID;

typedef struct _GUID *PGUID;

typedef struct _LARGE_INTEGER
    {
    __int64 QuadPart;
    } 	LARGE_INTEGER;

typedef struct _LARGE_INTEGER *PLARGE_INTEGER;

typedef struct _EVENT_DESCRIPTOR
    {
    USHORT Id;
    UCHAR Version;
    UCHAR Channel;
    UCHAR Level;
    UCHAR Opcode;
    USHORT Task;
    ULONGLONG Keyword;
    } 	EVENT_DESCRIPTOR;

typedef struct _EVENT_DESCRIPTOR *PEVENT_DESCRIPTOR;

typedef struct _EVENT_DESCRIPTOR *PCEVENT_DESCRIPTOR;

typedef struct _EVENT_HEADER
    {
    USHORT Size;
    USHORT HeaderType;
    USHORT Flags;
    USHORT EventProperty;
    ULONG ThreadId;
    ULONG ProcessId;
    LARGE_INTEGER TimeStamp;
    GUID ProviderId;
    EVENT_DESCRIPTOR EventDescriptor;
    union 
        {
        struct 
            {
            ULONG KernelTime;
            ULONG UserTime;
            } 	;
        ULONG64 ProcessorTime;
        } 	;
    GUID ActivityId;
    } 	EVENT_HEADER;

typedef struct _EVENT_HEADER *PEVENT_HEADER;

typedef DWORD LCID;

typedef struct _LUID
    {
    DWORD LowPart;
    LONG HighPart;
    } 	LUID;

typedef struct _LUID *PLUID;

typedef struct _MULTI_SZ
    {
    wchar_t *Value;
    DWORD nChar;
    } 	MULTI_SZ;

typedef struct _RPC_UNICODE_STRING
    {
    unsigned short Length;
    unsigned short MaximumLength;
    /* [length_is][size_is] */ WCHAR *Buffer;
    } 	RPC_UNICODE_STRING;

typedef struct _RPC_UNICODE_STRING *PRPC_UNICODE_STRING;

typedef struct _SERVER_INFO_100
    {
    DWORD sv100_platform_id;
    /* [string] */ wchar_t *sv100_name;
    } 	SERVER_INFO_100;

typedef struct _SERVER_INFO_100 *PSERVER_INFO_100;

typedef struct _SERVER_INFO_100 *LPSERVER_INFO_100;

typedef struct _SERVER_INFO_101
    {
    DWORD sv101_platform_id;
    /* [string] */ wchar_t *sv101_name;
    DWORD sv101_version_major;
    DWORD sv101_version_minor;
    DWORD sv101_version_type;
    /* [string] */ wchar_t *sv101_comment;
    } 	SERVER_INFO_101;

typedef struct _SERVER_INFO_101 *PSERVER_INFO_101;

typedef struct _SERVER_INFO_101 *LPSERVER_INFO_101;

typedef struct _SYSTEMTIME
    {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
    } 	SYSTEMTIME;

typedef struct _SYSTEMTIME *PSYSTEMTIME;

typedef struct _UINT128
    {
    UINT64 lower;
    UINT64 upper;
    } 	UINT128;

typedef struct _UINT128 *PUINT128;

typedef struct _ULARGE_INTEGER
    {
    unsigned __int64 QuadPart;
    } 	ULARGE_INTEGER;

typedef struct _ULARGE_INTEGER *PULARGE_INTEGER;

typedef struct _RPC_SID_IDENTIFIER_AUTHORITY
    {
    byte Value[ 6 ];
    } 	RPC_SID_IDENTIFIER_AUTHORITY;

typedef DWORD ACCESS_MASK;

typedef ACCESS_MASK *PACCESS_MASK;

typedef struct _OBJECT_TYPE_LIST
    {
    WORD Level;
    ACCESS_MASK Remaining;
    GUID *ObjectType;
    } 	OBJECT_TYPE_LIST;

typedef struct _OBJECT_TYPE_LIST *POBJECT_TYPE_LIST;

typedef struct _ACE_HEADER
    {
    UCHAR AceType;
    UCHAR AceFlags;
    USHORT AceSize;
    } 	ACE_HEADER;

typedef struct _ACE_HEADER *PACE_HEADER;

typedef struct _SYSTEM_MANDATORY_LABEL_ACE
    {
    ACE_HEADER Header;
    ACCESS_MASK Mask;
    DWORD SidStart;
    } 	SYSTEM_MANDATORY_LABEL_ACE;

typedef struct _SYSTEM_MANDATORY_LABEL_ACE *PSYSTEM_MANDATORY_LABEL_ACE;

typedef struct _TOKEN_MANDATORY_POLICY
    {
    DWORD Policy;
    } 	TOKEN_MANDATORY_POLICY;

typedef struct _TOKEN_MANDATORY_POLICY *PTOKEN_MANDATORY_POLICY;

typedef struct _MANDATORY_INFORMATION
    {
    ACCESS_MASK AllowedAccess;
    BOOLEAN WriteAllowed;
    BOOLEAN ReadAllowed;
    BOOLEAN ExecuteAllowed;
    TOKEN_MANDATORY_POLICY MandatoryPolicy;
    } 	MANDATORY_INFORMATION;

typedef struct _MANDATORY_INFORMATION *PMANDATORY_INFORMATION;

typedef struct _CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE
    {
    DWORD Length;
    BYTE OctetString[ 1 ];
    } 	CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE;

typedef struct _CLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE *PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE;

typedef struct _CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1
    {
    DWORD Name;
    WORD ValueType;
    WORD Reserved;
    DWORD Flags;
    DWORD ValueCount;
    union 
        {
        PLONG64 pInt64[ 1 ];
        PDWORD64 pUint64[ 1 ];
        PWSTR ppString[ 1 ];
        PCLAIM_SECURITY_ATTRIBUTE_OCTET_STRING_RELATIVE pOctetString[ 1 ];
        } 	Values;
    } 	CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1;

typedef struct _CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 *PCLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1;

typedef DWORD SECURITY_INFORMATION;

typedef DWORD *PSECURITY_INFORMATION;

typedef struct _RPC_SID
    {
    unsigned char Revision;
    unsigned char SubAuthorityCount;
    RPC_SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    /* [size_is] */ unsigned long SubAuthority[ 1 ];
    } 	RPC_SID;

typedef struct _RPC_SID *PRPC_SID;

typedef struct _RPC_SID *PSID;

typedef struct _ACL
    {
    unsigned char AclRevision;
    unsigned char Sbz1;
    unsigned short AclSize;
    unsigned short AceCount;
    unsigned short Sbz2;
    } 	ACL;

typedef struct _ACL *PACL;

typedef struct _SECURITY_DESCRIPTOR
    {
    UCHAR Revision;
    UCHAR Sbz1;
    USHORT Control;
    PSID Owner;
    PSID Group;
    PACL Sacl;
    PACL Dacl;
    } 	SECURITY_DESCRIPTOR;

typedef struct _SECURITY_DESCRIPTOR *PSECURITY_DESCRIPTOR;



extern RPC_IF_HANDLE __MIDL_itf_coerced_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_coerced_0000_0000_v0_0_s_ifspec;

#ifndef __efsrpc_INTERFACE_DEFINED__
#define __efsrpc_INTERFACE_DEFINED__

/* interface efsrpc */
/* [version][uuid] */ 

typedef /* [context_handle] */ void *PEXIMPORT_CONTEXT_HANDLE;

typedef struct pipe_EFS_EXIM_PIPE
    {
    void (__RPC_USER * pull) (
        char * state,
        unsigned char * buf,
        unsigned long esize,
        unsigned long * ecount );
    void (__RPC_USER * push) (
        char * state,
        unsigned char * buf,
        unsigned long ecount );
    void (__RPC_USER * alloc) (
        char * state,
        unsigned long bsize,
        unsigned char * * buf,
        unsigned long * bcount );
    char * state;
    } 	EFS_EXIM_PIPE;

typedef struct _EFS_RPC_BLOB
    {
    /* [range] */ DWORD cbData;
    /* [size_is] */ unsigned char *bData;
    } 	EFS_RPC_BLOB;

typedef struct _EFS_RPC_BLOB *PEFS_RPC_BLOB;

typedef /* [public] */ struct __MIDL_efsrpc_0004
    {
    DWORD EfsVersion;
    } 	EFS_COMPATIBILITY_INFO;

typedef unsigned int ALG_ID;

typedef struct _EFS_HASH_BLOB
    {
    /* [range] */ DWORD cbData;
    /* [size_is] */ unsigned char *bData;
    } 	EFS_HASH_BLOB;

typedef struct _ENCRYPTION_CERTIFICATE_HASH
    {
    DWORD cbTotalLength;
    RPC_SID *UserSid;
    EFS_HASH_BLOB *Hash;
    /* [string] */ wchar_t *lpDisplayInformation;
    } 	ENCRYPTION_CERTIFICATE_HASH;

typedef struct _ENCRYPTION_CERTIFICATE_HASH_LIST
    {
    /* [range] */ DWORD nCert_Hash;
    /* [size_is][size_is] */ ENCRYPTION_CERTIFICATE_HASH **Users;
    } 	ENCRYPTION_CERTIFICATE_HASH_LIST;

typedef struct _CERTIFICATE_BLOB
    {
    DWORD dwCertEncodingType;
    /* [range] */ DWORD cbData;
    /* [size_is] */ unsigned char *bData;
    } 	EFS_CERTIFICATE_BLOB;

typedef struct _ENCRYPTION_CERTIFICATE
    {
    DWORD cbTotalLength;
    RPC_SID *UserSid;
    EFS_CERTIFICATE_BLOB *CertBlob;
    } 	ENCRYPTION_CERTIFICATE;

typedef struct _ENCRYPTION_CERTIFICATE_LIST
    {
    /* [range] */ DWORD nUsers;
    /* [size_is][size_is] */ ENCRYPTION_CERTIFICATE **Users;
    } 	ENCRYPTION_CERTIFICATE_LIST;

typedef struct _ENCRYPTED_FILE_METADATA_SIGNATURE
    {
    DWORD dwEfsAccessType;
    ENCRYPTION_CERTIFICATE_HASH_LIST *CertificatesAdded;
    ENCRYPTION_CERTIFICATE *EncryptionCertificate;
    EFS_RPC_BLOB *EfsStreamSignature;
    } 	ENCRYPTED_FILE_METADATA_SIGNATURE;

typedef /* [public] */ struct __MIDL_efsrpc_0005
    {
    DWORD dwVersion;
    unsigned long Entropy;
    ALG_ID Algorithm;
    unsigned long KeyLength;
    } 	EFS_KEY_INFO;

typedef /* [public] */ struct __MIDL_efsrpc_0006
    {
    DWORD dwDecryptionError;
    DWORD dwHashOffset;
    DWORD cbHash;
    } 	EFS_DECRYPTION_STATUS_INFO;

typedef /* [public] */ struct __MIDL_efsrpc_0007
    {
    BOOL bHasCurrentKey;
    DWORD dwEncryptionError;
    } 	EFS_ENCRYPTION_STATUS_INFO;

typedef struct _ENCRYPTION_PROTECTOR
    {
    DWORD cbTotalLength;
    RPC_SID *UserSid;
    /* [string] */ wchar_t *lpProtectorDescriptor;
    } 	ENCRYPTION_PROTECTOR;

typedef struct _ENCRYPTION_PROTECTOR *PENCRYPTION_PROTECTOR;

typedef struct _ENCRYPTION_PROTECTOR_LIST
    {
    DWORD nProtectors;
    /* [size_is] */ PENCRYPTION_PROTECTOR *pProtectors;
    } 	ENCRYPTION_PROTECTOR_LIST;

typedef struct _ENCRYPTION_PROTECTOR_LIST *PENCRYPTION_PROTECTOR_LIST;

long EfsRpcOpenFileRaw( 
    /* [in] */ handle_t binding_h,
    /* [out] */ PEXIMPORT_CONTEXT_HANDLE *hContext,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ long Flags);

long EfsRpcReadFileRaw( 
    /* [in] */ PEXIMPORT_CONTEXT_HANDLE hContext,
    /* [out] */ EFS_EXIM_PIPE *EfsOutPipe);

long EfsRpcWriteFileRaw( 
    /* [in] */ PEXIMPORT_CONTEXT_HANDLE hContext,
    /* [in] */ EFS_EXIM_PIPE *EfsInPipe);

void EfsRpcCloseRaw( 
    /* [out][in] */ PEXIMPORT_CONTEXT_HANDLE *hContext);

long EfsRpcEncryptFileSrv( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName);

long EfsRpcDecryptFileSrv( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ unsigned long OpenFlag);

DWORD EfsRpcQueryUsersOnFile( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [out] */ ENCRYPTION_CERTIFICATE_HASH_LIST **Users);

DWORD EfsRpcQueryRecoveryAgents( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [out] */ ENCRYPTION_CERTIFICATE_HASH_LIST **RecoveryAgents);

DWORD EfsRpcRemoveUsersFromFile( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ ENCRYPTION_CERTIFICATE_HASH_LIST *Users);

DWORD EfsRpcAddUsersToFile( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ ENCRYPTION_CERTIFICATE_LIST *EncryptionCertificates);

void Opnum10NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

DWORD EfsRpcNotSupported( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *Reserved1,
    /* [string][in] */ wchar_t *Reserved2,
    /* [in] */ DWORD dwReserved1,
    /* [in] */ DWORD dwReserved2,
    /* [unique][in] */ EFS_RPC_BLOB *Reserved,
    /* [in] */ BOOL bReserved);

DWORD EfsRpcFileKeyInfo( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ DWORD InfoClass,
    /* [out] */ EFS_RPC_BLOB **KeyInfo);

DWORD EfsRpcDuplicateEncryptionInfoFile( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *SrcFileName,
    /* [string][in] */ wchar_t *DestFileName,
    /* [in] */ DWORD dwCreationDisposition,
    /* [in] */ DWORD dwAttributes,
    /* [unique][in] */ EFS_RPC_BLOB *RelativeSD,
    /* [in] */ BOOL bInheritHandle);

void Opnum14NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

DWORD EfsRpcAddUsersToFileEx( 
    /* [in] */ handle_t binding_h,
    /* [in] */ DWORD dwFlags,
    /* [unique][in] */ EFS_RPC_BLOB *Reserved,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ ENCRYPTION_CERTIFICATE_LIST *EncryptionCertificates);

DWORD EfsRpcFileKeyInfoEx( 
    /* [in] */ handle_t binding_h,
    /* [in] */ DWORD dwFileKeyInfoFlags,
    /* [unique][in] */ EFS_RPC_BLOB *Reserved,
    /* [string][in] */ wchar_t *FileName,
    /* [in] */ DWORD InfoClass,
    /* [out] */ EFS_RPC_BLOB **KeyInfo);

void Opnum17NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

DWORD EfsRpcGetEncryptedFileMetadata( 
    /* [in] */ handle_t binding_h,
    /* [ref][string][in] */ wchar_t *FileName,
    /* [ref][out] */ EFS_RPC_BLOB **EfsStreamBlob);

DWORD EfsRpcSetEncryptedFileMetadata( 
    /* [in] */ handle_t binding_h,
    /* [ref][string][in] */ wchar_t *FileName,
    /* [unique][in] */ EFS_RPC_BLOB *OldEfsStreamBlob,
    /* [ref][in] */ EFS_RPC_BLOB *NewEfsStreamBlob,
    /* [unique][in] */ ENCRYPTED_FILE_METADATA_SIGNATURE *NewEfsSignature);

DWORD EfsRpcFlushEfsCache( 
    /* [in] */ handle_t binding_h);

long EfsRpcEncryptFileExSrv( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [unique][string][in] */ wchar_t *ProtectorDescriptor,
    /* [in] */ unsigned long Flags);

DWORD EfsRpcQueryProtectors( 
    /* [in] */ handle_t binding_h,
    /* [string][in] */ wchar_t *FileName,
    /* [out] */ PENCRYPTION_PROTECTOR_LIST **ppProtectorList);

void Opnum23NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum24NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum25NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum26NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum27NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum28NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum29NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum30NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum31NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum32NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum33NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum34NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum35NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum36NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum37NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum38NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum39NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum40NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum41NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum42NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum43NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);

void Opnum44NotUsedOnWire( 
    /* [in] */ handle_t IDL_handle);



extern RPC_IF_HANDLE efsrpc_v1_0_c_ifspec;
extern RPC_IF_HANDLE efsrpc_v1_0_s_ifspec;
#endif /* __efsrpc_INTERFACE_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

void __RPC_USER PEXIMPORT_CONTEXT_HANDLE_rundown( PEXIMPORT_CONTEXT_HANDLE );

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif



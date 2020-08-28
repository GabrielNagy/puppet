require 'puppet/ffi/windows'

module Puppet::FFI::Windows
  module Constants
    extend FFI::Library

    FILE_ATTRIBUTE_READONLY      = 0x00000001
    FILE_ATTRIBUTE_DIRECTORY     = 0x00000010

    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379607(v=vs.85).aspx
    # The right to use the object for synchronization. This enables a thread to
    # wait until the object is in the signaled state. Some object types do not
    # support this access right.
    SYNCHRONIZE                 = 0x100000
    # The right to delete the object.
    DELETE                      = 0x00010000
    # The right to read the information in the object's security descriptor, not including the information in the system access control list (SACL).
    # READ_CONTROL              = 0x00020000
    # The right to modify the discretionary access control list (DACL) in the object's security descriptor.
    WRITE_DAC                   = 0x00040000
    # The right to change the owner in the object's security descriptor.
    WRITE_OWNER                 = 0x00080000

    # Combines DELETE, READ_CONTROL, WRITE_DAC, and WRITE_OWNER access.
    STANDARD_RIGHTS_REQUIRED    = 0xf0000
    # Currently defined to equal READ_CONTROL.
    STANDARD_RIGHTS_READ        = 0x20000
    # Currently defined to equal READ_CONTROL.
    STANDARD_RIGHTS_WRITE       = 0x20000
    # Currently defined to equal READ_CONTROL.
    STANDARD_RIGHTS_EXECUTE     = 0x20000
    # Combines DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, and SYNCHRONIZE access.
    STANDARD_RIGHTS_ALL         = 0x1F0000
    SPECIFIC_RIGHTS_ALL         = 0xFFFF

    FILE_READ_DATA               = 1
    FILE_WRITE_DATA              = 2
    FILE_APPEND_DATA             = 4
    FILE_READ_EA                 = 8
    FILE_WRITE_EA                = 16
    FILE_EXECUTE                 = 32
    FILE_DELETE_CHILD            = 64
    FILE_READ_ATTRIBUTES         = 128
    FILE_WRITE_ATTRIBUTES        = 256

    FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF

    FILE_GENERIC_READ =
       STANDARD_RIGHTS_READ |
       FILE_READ_DATA |
       FILE_READ_ATTRIBUTES |
       FILE_READ_EA |
       SYNCHRONIZE

    FILE_GENERIC_WRITE =
       STANDARD_RIGHTS_WRITE |
       FILE_WRITE_DATA |
       FILE_WRITE_ATTRIBUTES |
       FILE_WRITE_EA |
       FILE_APPEND_DATA |
       SYNCHRONIZE

    FILE_GENERIC_EXECUTE =
       STANDARD_RIGHTS_EXECUTE |
       FILE_READ_ATTRIBUTES |
       FILE_EXECUTE |
       SYNCHRONIZE

    REPLACEFILE_WRITE_THROUGH         = 0x1
    REPLACEFILE_IGNORE_MERGE_ERRORS   = 0x2
    REPLACEFILE_IGNORE_ACL_ERRORS     = 0x3

    INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF #define INVALID_FILE_ATTRIBUTES (DWORD (-1))

    IO_REPARSE_TAG_MOUNT_POINT  = 0xA0000003
    IO_REPARSE_TAG_HSM          = 0xC0000004
    IO_REPARSE_TAG_HSM2         = 0x80000006
    IO_REPARSE_TAG_SIS          = 0x80000007
    IO_REPARSE_TAG_WIM          = 0x80000008
    IO_REPARSE_TAG_CSV          = 0x80000009
    IO_REPARSE_TAG_DFS          = 0x8000000A
    IO_REPARSE_TAG_SYMLINK      = 0xA000000C
    IO_REPARSE_TAG_DFSR         = 0x80000012
    IO_REPARSE_TAG_DEDUP        = 0x80000013
    IO_REPARSE_TAG_NFS          = 0x80000014

    FILE_ATTRIBUTE_REPARSE_POINT = 0x400

    GENERIC_READ                  = 0x80000000
    GENERIC_WRITE                 = 0x40000000
    GENERIC_EXECUTE               = 0x20000000
    GENERIC_ALL                   = 0x10000000
    METHOD_BUFFERED               = 0
    FILE_SHARE_READ               = 1
    FILE_SHARE_WRITE              = 2
    OPEN_EXISTING                 = 3
    FILE_DEVICE_FILE_SYSTEM       = 0x00000009
    FILE_FLAG_OPEN_REPARSE_POINT  = 0x00200000
    FILE_FLAG_BACKUP_SEMANTICS    = 0x02000000
    SHGFI_DISPLAYNAME             = 0x000000200
    SHGFI_PIDL                    = 0x000000008

    ERROR_FILE_NOT_FOUND = 2
    ERROR_PATH_NOT_FOUND = 3
    ERROR_ACCESS_DENIED  = 5
    ERROR_ALREADY_EXISTS = 183

    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa364571(v=vs.85).aspx
    FSCTL_GET_REPARSE_POINT = 0x900a8

    MAXIMUM_REPARSE_DATA_BUFFER_SIZE = 16384

    # Priority constants
    # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setpriorityclass
    ABOVE_NORMAL_PRIORITY_CLASS = 0x0008000
    BELOW_NORMAL_PRIORITY_CLASS = 0x0004000
    HIGH_PRIORITY_CLASS         = 0x0000080
    IDLE_PRIORITY_CLASS         = 0x0000040
    NORMAL_PRIORITY_CLASS       = 0x0000020
    REALTIME_PRIORITY_CLASS     = 0x0000010

    # Process Access Rights
    # https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
    PROCESS_TERMINATE         = 0x00000001
    PROCESS_SET_INFORMATION   = 0x00000200
    PROCESS_QUERY_INFORMATION = 0x00000400
    PROCESS_ALL_ACCESS        = 0x001F0FFF
    PROCESS_VM_READ           = 0x00000010

    # Process creation flags
    # https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
    CREATE_BREAKAWAY_FROM_JOB        = 0x01000000
    CREATE_DEFAULT_ERROR_MODE        = 0x04000000
    CREATE_NEW_CONSOLE               = 0x00000010
    CREATE_NEW_PROCESS_GROUP         = 0x00000200
    CREATE_NO_WINDOW                 = 0x08000000
    CREATE_PROTECTED_PROCESS         = 0x00040000
    CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000
    CREATE_SEPARATE_WOW_VDM          = 0x00000800
    CREATE_SHARED_WOW_VDM            = 0x00001000
    CREATE_SUSPENDED                 = 0x00000004
    CREATE_UNICODE_ENVIRONMENT       = 0x00000400
    DEBUG_ONLY_THIS_PROCESS          = 0x00000002
    DEBUG_PROCESS                    = 0x00000001
    DETACHED_PROCESS                 = 0x00000008
    INHERIT_PARENT_AFFINITY          = 0x00010000

    # Logon options
    LOGON_WITH_PROFILE        = 0x00000001

    # STARTUPINFOA constants
    # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    STARTF_USESTDHANDLES    = 0x00000100

    # Miscellaneous
    HANDLE_FLAG_INHERIT     = 0x00000001
    SEM_FAILCRITICALERRORS  = 0x00000001
    SEM_NOGPFAULTERRORBOX   = 0x00000002

    # Error constants
    INVALID_HANDLE_VALUE = FFI::Pointer.new(-1).address

    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379626(v=vs.85).aspx
    TOKEN_INFORMATION_CLASS = enum(
        :TokenUser, 1,
        :TokenGroups,
        :TokenPrivileges,
        :TokenOwner,
        :TokenPrimaryGroup,
        :TokenDefaultDacl,
        :TokenSource,
        :TokenType,
        :TokenImpersonationLevel,
        :TokenStatistics,
        :TokenRestrictedSids,
        :TokenSessionId,
        :TokenGroupsAndPrivileges,
        :TokenSessionReference,
        :TokenSandBoxInert,
        :TokenAuditPolicy,
        :TokenOrigin,
        :TokenElevationType,
        :TokenLinkedToken,
        :TokenElevation,
        :TokenHasRestrictions,
        :TokenAccessInformation,
        :TokenVirtualizationAllowed,
        :TokenVirtualizationEnabled,
        :TokenIntegrityLevel,
        :TokenUIAccess,
        :TokenMandatoryPolicy,
        :TokenLogonSid,
        :TokenIsAppContainer,
        :TokenCapabilities,
        :TokenAppContainerSid,
        :TokenAppContainerNumber,
        :TokenUserClaimAttributes,
        :TokenDeviceClaimAttributes,
        :TokenRestrictedUserClaimAttributes,
        :TokenRestrictedDeviceClaimAttributes,
        :TokenDeviceGroups,
        :TokenRestrictedDeviceGroups,
        :TokenSecurityAttributes,
        :TokenIsRestricted,
        :MaxTokenInfoClass
    )

    # Service error codes
    # https://docs.microsoft.com/en-us/windows/desktop/debug/system-error-codes--1000-1299-
    ERROR_SERVICE_DOES_NOT_EXIST = 0x00000424

    # Service control codes
    # https://docs.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-controlserviceexw
    SERVICE_CONTROL_STOP                  = 0x00000001
    SERVICE_CONTROL_PAUSE                 = 0x00000002
    SERVICE_CONTROL_CONTINUE              = 0x00000003
    SERVICE_CONTROL_INTERROGATE           = 0x00000004
    SERVICE_CONTROL_SHUTDOWN              = 0x00000005
    SERVICE_CONTROL_PARAMCHANGE           = 0x00000006
    SERVICE_CONTROL_NETBINDADD            = 0x00000007
    SERVICE_CONTROL_NETBINDREMOVE         = 0x00000008
    SERVICE_CONTROL_NETBINDENABLE         = 0x00000009
    SERVICE_CONTROL_NETBINDDISABLE        = 0x0000000A
    SERVICE_CONTROL_DEVICEEVENT           = 0x0000000B
    SERVICE_CONTROL_HARDWAREPROFILECHANGE = 0x0000000C
    SERVICE_CONTROL_POWEREVENT            = 0x0000000D
    SERVICE_CONTROL_SESSIONCHANGE         = 0x0000000E
    SERVICE_CONTROL_PRESHUTDOWN           = 0x0000000F
    SERVICE_CONTROL_TIMECHANGE            = 0x00000010
    SERVICE_CONTROL_TRIGGEREVENT          = 0x00000020
    SERVICE_CONTROL_SIGNALS               = {
      SERVICE_CONTROL_STOP                  => :SERVICE_CONTROL_STOP,
      SERVICE_CONTROL_PAUSE                 => :SERVICE_CONTROL_PAUSE,
      SERVICE_CONTROL_CONTINUE              => :SERVICE_CONTROL_CONTINUE,
      SERVICE_CONTROL_INTERROGATE           => :SERVICE_CONTROL_INTERROGATE,
      SERVICE_CONTROL_SHUTDOWN              => :SERVICE_CONTROL_SHUTDOWN,
      SERVICE_CONTROL_PARAMCHANGE           => :SERVICE_CONTROL_PARAMCHANGE,
      SERVICE_CONTROL_NETBINDADD            => :SERVICE_CONTROL_NETBINDADD,
      SERVICE_CONTROL_NETBINDREMOVE         => :SERVICE_CONTROL_NETBINDREMOVE,
      SERVICE_CONTROL_NETBINDENABLE         => :SERVICE_CONTROL_NETBINDENABLE,
      SERVICE_CONTROL_NETBINDDISABLE        => :SERVICE_CONTROL_NETBINDDISABLE,
      SERVICE_CONTROL_DEVICEEVENT           => :SERVICE_CONTROL_DEVICEEVENT,
      SERVICE_CONTROL_HARDWAREPROFILECHANGE => :SERVICE_CONTROL_HARDWAREPROFILECHANGE,
      SERVICE_CONTROL_POWEREVENT            => :SERVICE_CONTROL_POWEREVENT,
      SERVICE_CONTROL_SESSIONCHANGE         => :SERVICE_CONTROL_SESSIONCHANGE,
      SERVICE_CONTROL_PRESHUTDOWN           => :SERVICE_CONTROL_PRESHUTDOWN,
      SERVICE_CONTROL_TIMECHANGE            => :SERVICE_CONTROL_TIMECHANGE,
      SERVICE_CONTROL_TRIGGEREVENT          => :SERVICE_CONTROL_TRIGGEREVENT
    }

    # Service start type codes
    # https://docs.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-changeserviceconfigw
    SERVICE_AUTO_START = 0x00000002
    SERVICE_BOOT_START = 0x00000000
    SERVICE_DEMAND_START = 0x00000003
    SERVICE_DISABLED = 0x00000004
    SERVICE_SYSTEM_START = 0x00000001
    SERVICE_START_TYPES = {
      SERVICE_AUTO_START => :SERVICE_AUTO_START,
      SERVICE_BOOT_START => :SERVICE_BOOT_START,
      SERVICE_DEMAND_START => :SERVICE_DEMAND_START,
      SERVICE_DISABLED => :SERVICE_DISABLED,
      SERVICE_SYSTEM_START => :SERVICE_SYSTEM_START,
    }

    # Service type codes
    # https://docs.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-changeserviceconfigw
    SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002
    SERVICE_KERNEL_DRIVER       = 0x00000001
    SERVICE_WIN32_OWN_PROCESS   = 0x00000010
    SERVICE_WIN32_SHARE_PROCESS = 0x00000020
    SERVICE_USER_OWN_PROCESS    = 0x00000050
    SERVICE_USER_SHARE_PROCESS  = 0x00000060
    # Available only if service is also SERVICE_WIN32_OWN_PROCESS or SERVICE_WIN32_SHARE_PROCESS
    SERVICE_INTERACTIVE_PROCESS = 0x00000100
    ALL_SERVICE_TYPES =
      SERVICE_FILE_SYSTEM_DRIVER |
      SERVICE_KERNEL_DRIVER |
      SERVICE_WIN32_OWN_PROCESS |
      SERVICE_WIN32_SHARE_PROCESS

    # Current state codes
    # https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/ns-winsvc-_service_status_process
    SERVICE_CONTINUE_PENDING = 0x00000005
    SERVICE_PAUSE_PENDING    = 0x00000006
    SERVICE_PAUSED           = 0x00000007
    SERVICE_RUNNING          = 0x00000004
    SERVICE_START_PENDING    = 0x00000002
    SERVICE_STOP_PENDING     = 0x00000003
    SERVICE_STOPPED          = 0x00000001
    UNSAFE_PENDING_STATES    = [SERVICE_START_PENDING, SERVICE_STOP_PENDING]
    FINAL_STATES             = {
      SERVICE_CONTINUE_PENDING => SERVICE_RUNNING,
      SERVICE_PAUSE_PENDING    => SERVICE_PAUSED,
      SERVICE_START_PENDING    => SERVICE_RUNNING,
      SERVICE_STOP_PENDING     => SERVICE_STOPPED
    }
    SERVICE_STATES           = {
      SERVICE_CONTINUE_PENDING => :SERVICE_CONTINUE_PENDING,
      SERVICE_PAUSE_PENDING => :SERVICE_PAUSE_PENDING,
      SERVICE_PAUSED => :SERVICE_PAUSED,
      SERVICE_RUNNING => :SERVICE_RUNNING,
      SERVICE_START_PENDING => :SERVICE_START_PENDING,
      SERVICE_STOP_PENDING => :SERVICE_STOP_PENDING,
      SERVICE_STOPPED => :SERVICE_STOPPED,
    }

    # Service accepts control codes
    # https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/ns-winsvc-_service_status_process
    SERVICE_ACCEPT_STOP                  = 0x00000001
    SERVICE_ACCEPT_PAUSE_CONTINUE        = 0x00000002
    SERVICE_ACCEPT_SHUTDOWN              = 0x00000004
    SERVICE_ACCEPT_PARAMCHANGE           = 0x00000008
    SERVICE_ACCEPT_NETBINDCHANGE         = 0x00000010
    SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020
    SERVICE_ACCEPT_POWEREVENT            = 0x00000040
    SERVICE_ACCEPT_SESSIONCHANGE         = 0x00000080
    SERVICE_ACCEPT_PRESHUTDOWN           = 0x00000100
    SERVICE_ACCEPT_TIMECHANGE            = 0x00000200
    SERVICE_ACCEPT_TRIGGEREVENT          = 0x00000400
    SERVICE_ACCEPT_USER_LOGOFF           = 0x00000800

    # Service manager access codes
    # https://docs.microsoft.com/en-us/windows/desktop/Services/service-security-and-access-rights
    SC_MANAGER_CREATE_SERVICE     = 0x00000002
    SC_MANAGER_CONNECT            = 0x00000001
    SC_MANAGER_ENUMERATE_SERVICE  = 0x00000004
    SC_MANAGER_LOCK               = 0x00000008
    SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00000020
    SC_MANAGER_QUERY_LOCK_STATUS  = 0x00000010
    SC_MANAGER_ALL_ACCESS         =
      STANDARD_RIGHTS_REQUIRED |
      SC_MANAGER_CREATE_SERVICE      |
      SC_MANAGER_CONNECT             |
      SC_MANAGER_ENUMERATE_SERVICE   |
      SC_MANAGER_LOCK                |
      SC_MANAGER_MODIFY_BOOT_CONFIG  |
      SC_MANAGER_QUERY_LOCK_STATUS

    # Service access codes
    # https://docs.microsoft.com/en-us/windows/desktop/Services/service-security-and-access-rights
    SERVICE_CHANGE_CONFIG        = 0x0002
    SERVICE_ENUMERATE_DEPENDENTS = 0x0008
    SERVICE_INTERROGATE          = 0x0080
    SERVICE_PAUSE_CONTINUE       = 0x0040
    SERVICE_QUERY_STATUS         = 0x0004
    SERVICE_QUERY_CONFIG         = 0x0001
    SERVICE_START                = 0x0010
    SERVICE_STOP                 = 0x0020
    SERVICE_USER_DEFINED_CONTROL = 0x0100
    SERVICE_ALL_ACCESS           =
      STANDARD_RIGHTS_REQUIRED |
      SERVICE_CHANGE_CONFIG          |
      SERVICE_ENUMERATE_DEPENDENTS   |
      SERVICE_INTERROGATE            |
      SERVICE_PAUSE_CONTINUE         |
      SERVICE_QUERY_STATUS           |
      SERVICE_QUERY_CONFIG           |
      SERVICE_START                  |
      SERVICE_STOP                   |
      SERVICE_USER_DEFINED_CONTROL

    # Service config codes
    # From the windows 10 SDK:
    # //
    # // Value to indicate no change to an optional parameter
    # //
    # #define SERVICE_NO_CHANGE              0xffffffff
    # https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w
    SERVICE_CONFIG_DESCRIPTION              = 0x00000001
    SERVICE_CONFIG_FAILURE_ACTIONS          = 0x00000002
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO  = 0x00000003
    SERVICE_CONFIG_FAILURE_ACTIONS_FLAG     = 0x00000004
    SERVICE_CONFIG_SERVICE_SID_INFO         = 0x00000005
    SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 0x00000006
    SERVICE_CONFIG_PRESHUTDOWN_INFO         = 0x00000007
    SERVICE_CONFIG_TRIGGER_INFO             = 0x00000008
    SERVICE_CONFIG_PREFERRED_NODE           = 0x00000009
    SERVICE_CONFIG_LAUNCH_PROTECTED         = 0x00000012
    SERVICE_NO_CHANGE                       = 0xffffffff
    SERVICE_CONFIG_TYPES = {
      SERVICE_CONFIG_DESCRIPTION => :SERVICE_CONFIG_DESCRIPTION,
      SERVICE_CONFIG_FAILURE_ACTIONS => :SERVICE_CONFIG_FAILURE_ACTIONS,
      SERVICE_CONFIG_DELAYED_AUTO_START_INFO => :SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
      SERVICE_CONFIG_FAILURE_ACTIONS_FLAG => :SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
      SERVICE_CONFIG_SERVICE_SID_INFO => :SERVICE_CONFIG_SERVICE_SID_INFO,
      SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO => :SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
      SERVICE_CONFIG_PRESHUTDOWN_INFO => :SERVICE_CONFIG_PRESHUTDOWN_INFO,
      SERVICE_CONFIG_TRIGGER_INFO => :SERVICE_CONFIG_TRIGGER_INFO,
      SERVICE_CONFIG_PREFERRED_NODE => :SERVICE_CONFIG_PREFERRED_NODE,
      SERVICE_CONFIG_LAUNCH_PROTECTED => :SERVICE_CONFIG_LAUNCH_PROTECTED,
    }

    # Service enum codes
    # https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/nf-winsvc-enumservicesstatusexa
    SERVICE_ACTIVE = 0x00000001
    SERVICE_INACTIVE = 0x00000002
    SERVICE_STATE_ALL =
      SERVICE_ACTIVE |
      SERVICE_INACTIVE

    # https://docs.microsoft.com/en-us/windows/desktop/api/winsvc/ns-winsvc-_enum_service_status_processw
    SERVICENAME_MAX = 256

    # Puppet::Util::Windows::Registry constants
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa384129(v=vs.85).aspx
    KEY64 = 0x100
    KEY32 = 0x200

    KEY_READ       = 0x20019
    KEY_WRITE      = 0x20006
    KEY_ALL_ACCESS = 0x2003f

    ERROR_NO_MORE_ITEMS = 259

    # max number of wide characters including NULL terminator
    MAX_KEY_CHAR_LENGTH = 255 + 1

    # max number of wide characters including NULL terminator
    MAX_VALUE_CHAR_LENGTH = 16383 + 1

    # Puppet::Util::Windows::SID class constants
    # missing from Windows::Error
    ERROR_NONE_MAPPED           = 1332
    ERROR_INVALID_SID_STRUCTURE = 1337

    # https://stackoverflow.com/a/1792930 - 68 bytes, 184 characters in a string
    MAXIMUM_SID_STRING_LENGTH = 184

    # Puppet::Util::Windows::EventLog class constants
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa363679(v=vs.85).aspx
    EVENTLOG_ERROR_TYPE       = 0x0001
    EVENTLOG_WARNING_TYPE     = 0x0002
    EVENTLOG_INFORMATION_TYPE = 0x0004

    # These are duplicate definitions from Puppet::Util::Windows::ApiTypes,
    # established here so this class can be standalone from Puppet, and public so
    # we can reference them in tests.
    NULL_HANDLE = 0
    WIN32_FALSE = 0

    # Puppet::Util::Windows::Error class constants
    FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
    FORMAT_MESSAGE_IGNORE_INSERTS  = 0x00000200
    FORMAT_MESSAGE_FROM_SYSTEM     = 0x00001000
    FORMAT_MESSAGE_ARGUMENT_ARRAY  = 0x00002000
    FORMAT_MESSAGE_MAX_WIDTH_MASK  = 0x000000FF

    # Puppet::Util::Windows::ADSI constants
    # https://docs.microsoft.com/en-us/windows/win32/api/dsrole/ne-dsrole-dsrole_machine_role
    STANDALONE_WORKSTATION = 0
    MEMBER_WORKSTATION = 1
    STANDALONE_SERVER = 2
    MEMBER_SERVER = 3
    BACKUP_DOMAIN_CONTROLLER = 4
    PRIMARY_DOMAIN_CONTROLLER = 5

    DOMAIN_ROLES = {
      STANDALONE_WORKSTATION => :STANDALONE_WORKSTATION,
      MEMBER_WORKSTATION => :MEMBER_WORKSTATION,
      STANDALONE_SERVER => :STANDALONE_SERVER,
      MEMBER_SERVER => :MEMBER_SERVER,
      BACKUP_DOMAIN_CONTROLLER => :BACKUP_DOMAIN_CONTROLLER,
      PRIMARY_DOMAIN_CONTROLLER => :PRIMARY_DOMAIN_CONTROLLER,
    }

    # taken from winbase.h
    MAX_COMPUTERNAME_LENGTH = 31

    # Declare all of the available user flags on the system. Note that
    # ADS_UF is read as ADS_UserFlag
    #   https://docs.microsoft.com/en-us/windows/desktop/api/iads/ne-iads-ads_user_flag
    # and
    #   https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro
    # for the flag values.
    ADS_USERFLAGS = {
      ADS_UF_SCRIPT:                                 0x0001,
      ADS_UF_ACCOUNTDISABLE:                         0x0002,
      ADS_UF_HOMEDIR_REQUIRED:                       0x0008,
      ADS_UF_LOCKOUT:                                0x0010,
      ADS_UF_PASSWD_NOTREQD:                         0x0020,
      ADS_UF_PASSWD_CANT_CHANGE:                     0x0040,
      ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED:        0x0080,
      ADS_UF_TEMP_DUPLICATE_ACCOUNT:                 0x0100,
      ADS_UF_NORMAL_ACCOUNT:                         0x0200,
      ADS_UF_INTERDOMAIN_TRUST_ACCOUNT:              0x0800,
      ADS_UF_WORKSTATION_TRUST_ACCOUNT:              0x1000,
      ADS_UF_SERVER_TRUST_ACCOUNT:                   0x2000,
      ADS_UF_DONT_EXPIRE_PASSWD:                     0x10000,
      ADS_UF_MNS_LOGON_ACCOUNT:                      0x20000,
      ADS_UF_SMARTCARD_REQUIRED:                     0x40000,
      ADS_UF_TRUSTED_FOR_DELEGATION:                 0x80000,
      ADS_UF_NOT_DELEGATED:                          0x100000,
      ADS_UF_USE_DES_KEY_ONLY:                       0x200000,
      ADS_UF_DONT_REQUIRE_PREAUTH:                   0x400000,
      ADS_UF_PASSWORD_EXPIRED:                       0x800000,
      ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: 0x1000000
    }

    # Puppet::Util::Windows::User constants
    # https://msdn.microsoft.com/en-us/library/windows/desktop/ee207397(v=vs.85).aspx
    SECURITY_MAX_SID_SIZE = 68

    # https://msdn.microsoft.com/en-us/library/windows/desktop/ms681385(v=vs.85).aspx
    # These error codes indicate successful authentication but failure to
    # logon for a separate reason
    ERROR_ACCOUNT_RESTRICTION = 1327
    ERROR_INVALID_LOGON_HOURS = 1328
    ERROR_INVALID_WORKSTATION = 1329
    ERROR_ACCOUNT_DISABLED    = 1331

    # ACCESS_MASK flags for Policy Objects
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/b61b7268-987a-420b-84f9-6c75f8dc8558
    POLICY_VIEW_LOCAL_INFORMATION   = 0x00000001
    POLICY_VIEW_AUDIT_INFORMATION   = 0x00000002
    POLICY_GET_PRIVATE_INFORMATION  = 0x00000004
    POLICY_TRUST_ADMIN              = 0x00000008
    POLICY_CREATE_ACCOUNT           = 0x00000010
    POLICY_CREATE_SECRET            = 0x00000020
    POLICY_CREATE_PRIVILEGE         = 0x00000040
    POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080
    POLICY_SET_AUDIT_REQUIREMENTS   = 0x00000100
    POLICY_AUDIT_LOG_ADMIN          = 0x00000200
    POLICY_SERVER_ADMIN             = 0x00000400
    POLICY_LOOKUP_NAMES             = 0x00000800
    POLICY_NOTIFICATION             = 0x00001000

    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379650(v=vs.85).aspx
    WELL_KNOWN_SID_TYPE = enum(
      :WinNullSid                                   , 0,
      :WinWorldSid                                  , 1,
      :WinLocalSid                                  , 2,
      :WinCreatorOwnerSid                           , 3,
      :WinCreatorGroupSid                           , 4,
      :WinCreatorOwnerServerSid                     , 5,
      :WinCreatorGroupServerSid                     , 6,
      :WinNtAuthoritySid                            , 7,
      :WinDialupSid                                 , 8,
      :WinNetworkSid                                , 9,
      :WinBatchSid                                  , 10,
      :WinInteractiveSid                            , 11,
      :WinServiceSid                                , 12,
      :WinAnonymousSid                              , 13,
      :WinProxySid                                  , 14,
      :WinEnterpriseControllersSid                  , 15,
      :WinSelfSid                                   , 16,
      :WinAuthenticatedUserSid                      , 17,
      :WinRestrictedCodeSid                         , 18,
      :WinTerminalServerSid                         , 19,
      :WinRemoteLogonIdSid                          , 20,
      :WinLogonIdsSid                               , 21,
      :WinLocalSystemSid                            , 22,
      :WinLocalServiceSid                           , 23,
      :WinNetworkServiceSid                         , 24,
      :WinBuiltinDomainSid                          , 25,
      :WinBuiltinAdministratorsSid                  , 26,
      :WinBuiltinUsersSid                           , 27,
      :WinBuiltinGuestsSid                          , 28,
      :WinBuiltinPowerUsersSid                      , 29,
      :WinBuiltinAccountOperatorsSid                , 30,
      :WinBuiltinSystemOperatorsSid                 , 31,
      :WinBuiltinPrintOperatorsSid                  , 32,
      :WinBuiltinBackupOperatorsSid                 , 33,
      :WinBuiltinReplicatorSid                      , 34,
      :WinBuiltinPreWindows2000CompatibleAccessSid  , 35,
      :WinBuiltinRemoteDesktopUsersSid              , 36,
      :WinBuiltinNetworkConfigurationOperatorsSid   , 37,
      :WinAccountAdministratorSid                   , 38,
      :WinAccountGuestSid                           , 39,
      :WinAccountKrbtgtSid                          , 40,
      :WinAccountDomainAdminsSid                    , 41,
      :WinAccountDomainUsersSid                     , 42,
      :WinAccountDomainGuestsSid                    , 43,
      :WinAccountComputersSid                       , 44,
      :WinAccountControllersSid                     , 45,
      :WinAccountCertAdminsSid                      , 46,
      :WinAccountSchemaAdminsSid                    , 47,
      :WinAccountEnterpriseAdminsSid                , 48,
      :WinAccountPolicyAdminsSid                    , 49,
      :WinAccountRasAndIasServersSid                , 50,
      :WinNTLMAuthenticationSid                     , 51,
      :WinDigestAuthenticationSid                   , 52,
      :WinSChannelAuthenticationSid                 , 53,
      :WinThisOrganizationSid                       , 54,
      :WinOtherOrganizationSid                      , 55,
      :WinBuiltinIncomingForestTrustBuildersSid     , 56,
      :WinBuiltinPerfMonitoringUsersSid             , 57,
      :WinBuiltinPerfLoggingUsersSid                , 58,
      :WinBuiltinAuthorizationAccessSid             , 59,
      :WinBuiltinTerminalServerLicenseServersSid    , 60,
      :WinBuiltinDCOMUsersSid                       , 61,
      :WinBuiltinIUsersSid                          , 62,
      :WinIUserSid                                  , 63,
      :WinBuiltinCryptoOperatorsSid                 , 64,
      :WinUntrustedLabelSid                         , 65,
      :WinLowLabelSid                               , 66,
      :WinMediumLabelSid                            , 67,
      :WinHighLabelSid                              , 68,
      :WinSystemLabelSid                            , 69,
      :WinWriteRestrictedCodeSid                    , 70,
      :WinCreatorOwnerRightsSid                     , 71,
      :WinCacheablePrincipalsGroupSid               , 72,
      :WinNonCacheablePrincipalsGroupSid            , 73,
      :WinEnterpriseReadonlyControllersSid          , 74,
      :WinAccountReadonlyControllersSid             , 75,
      :WinBuiltinEventLogReadersGroup               , 76,
      :WinNewEnterpriseReadonlyControllersSid       , 77,
      :WinBuiltinCertSvcDComAccessGroup             , 78,
      :WinMediumPlusLabelSid                        , 79,
      :WinLocalLogonSid                             , 80,
      :WinConsoleLogonSid                           , 81,
      :WinThisOrganizationCertificateSid            , 82,
      :WinApplicationPackageAuthoritySid            , 83,
      :WinBuiltinAnyPackageSid                      , 84,
      :WinCapabilityInternetClientSid               , 85,
      :WinCapabilityInternetClientServerSid         , 86,
      :WinCapabilityPrivateNetworkClientServerSid   , 87,
      :WinCapabilityPicturesLibrarySid              , 88,
      :WinCapabilityVideosLibrarySid                , 89,
      :WinCapabilityMusicLibrarySid                 , 90,
      :WinCapabilityDocumentsLibrarySid             , 91,
      :WinCapabilitySharedUserCertificatesSid       , 92,
      :WinCapabilityEnterpriseAuthenticationSid     , 93,
      :WinCapabilityRemovableStorageSid             , 94
    )

    # Puppet::Util::Windows::Process constants
    WAIT_TIMEOUT = 0x102
    WAIT_INTERVAL = 200
    # https://docs.microsoft.com/en-us/windows/desktop/ProcThread/process-creation-flags
    CREATE_NO_WINDOW = 0x08000000
    # https://docs.microsoft.com/en-us/windows/desktop/ProcThread/process-security-and-access-rights
    PROCESS_QUERY_INFORMATION = 0x0400
    # https://docs.microsoft.com/en-us/windows/desktop/FileIO/naming-a-file#maximum-path-length-limitation
    MAX_PATH_LENGTH = 32767

    TOKEN_ALL_ACCESS = 0xF01FF
    TOKEN_QUERY = 0x0008
    ERROR_NO_SUCH_PRIVILEGE = 1313

    # Puppet::Util::Windows::SID::Principal constants
    # = 8 + max sub identifiers (15) * 4
    MAXIMUM_SID_BYTE_LENGTH = 68

    ERROR_INVALID_PARAMETER   = 87
    ERROR_INSUFFICIENT_BUFFER = 122

    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa379601(v=vs.85).aspx
    SID_NAME_USE = enum(
      :SidTypeUser, 1,
      :SidTypeGroup, 2,
      :SidTypeDomain, 3,
      :SidTypeAlias, 4,
      :SidTypeWellKnownGroup, 5,
      :SidTypeDeletedAccount, 6,
      :SidTypeInvalid, 7,
      :SidTypeUnknown, 8,
      :SidTypeComputer, 9,
      :SidTypeLabel, 10
    )
  end
end

require 'puppet/util/windows'

require 'facter'

module Puppet::Util::Windows::User
  extend Puppet::Util::Windows::String

  extend Puppet::FFI::Windows::Functions
  extend Puppet::FFI::Windows::Constants
  extend Puppet::FFI::Windows::Structs

  def admin?
    return false unless check_token_membership

    # if Vista or later, check for unrestricted process token
    elevated_supported = Puppet::Util::Windows::Process.supports_elevated_security?
    return elevated_supported ? Puppet::Util::Windows::Process.elevated_security? : true
  end
  module_function :admin?

  # The name of the account in all locales is `LocalSystem`. `.\LocalSystem` or `ComputerName\LocalSystem' can also be used.
  # This account is not recognized by the security subsystem, so you cannot specify its name in a call to the `LookupAccountName` function.
  # https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account
  def localsystem?(name)
    ["LocalSystem", ".\\LocalSystem", "#{Puppet::Util::Windows::ADSI.computer_name}\\LocalSystem"].any?{ |s| s.casecmp(name) == 0 }
  end
  module_function :localsystem?

  # Check if a given user is one of the default system accounts
  # These accounts do not have a password and all checks done through logon attempt will fail
  # https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts#default-local-system-accounts
  def default_system_account?(name)
    user_sid = Puppet::Util::Windows::SID.name_to_sid(name)
    [Puppet::Util::Windows::SID::LocalSystem, Puppet::Util::Windows::SID::NtLocal, Puppet::Util::Windows::SID::NtNetwork].include?(user_sid)
  end
  module_function :default_system_account?

  def check_token_membership
    is_admin = false
    FFI::MemoryPointer.new(:byte, SECURITY_MAX_SID_SIZE) do |sid_pointer|
      FFI::MemoryPointer.new(:dword, 1) do |size_pointer|
        size_pointer.write_uint32(SECURITY_MAX_SID_SIZE)

        if CreateWellKnownSid(:WinBuiltinAdministratorsSid, FFI::Pointer::NULL, sid_pointer, size_pointer) == FFI::WIN32_FALSE
          raise Puppet::Util::Windows::Error.new(_("Failed to create administrators SID"))
        end
      end

      if IsValidSid(sid_pointer) == FFI::WIN32_FALSE
        raise Puppet::Util::Windows::Error.new(_("Invalid SID"))
      end

      FFI::MemoryPointer.new(:win32_bool, 1) do |ismember_pointer|
        if CheckTokenMembership(FFI::Pointer::NULL_HANDLE, sid_pointer, ismember_pointer) == FFI::WIN32_FALSE
          raise Puppet::Util::Windows::Error.new(_("Failed to check membership"))
        end

        # Is administrators SID enabled in calling thread's access token?
        is_admin = ismember_pointer.read_win32_bool
      end
    end

    is_admin
  end
  module_function :check_token_membership

  def password_is?(name, password, domain = '.')
    begin
      logon_user(name, password, domain) { |token| }
    rescue Puppet::Util::Windows::Error => detail

      authenticated_error_codes = Set[
        ERROR_ACCOUNT_RESTRICTION,
        ERROR_INVALID_LOGON_HOURS,
        ERROR_INVALID_WORKSTATION,
        ERROR_ACCOUNT_DISABLED,
      ]

      return authenticated_error_codes.include?(detail.code)
    end
  end
  module_function :password_is?

  def logon_user(name, password, domain = '.', &block)
    fLOGON32_PROVIDER_DEFAULT = 0
    fLOGON32_LOGON_INTERACTIVE = 2
    fLOGON32_LOGON_NETWORK = 3

    token = nil
    begin
      FFI::MemoryPointer.new(:handle, 1) do |token_pointer|
        #try logon using network else try logon using interactive mode
        if logon_user_by_logon_type(name, domain, password, fLOGON32_LOGON_NETWORK, fLOGON32_PROVIDER_DEFAULT, token_pointer) == FFI::WIN32_FALSE
          if logon_user_by_logon_type(name, domain, password, fLOGON32_LOGON_INTERACTIVE, fLOGON32_PROVIDER_DEFAULT, token_pointer) == FFI::WIN32_FALSE
            raise Puppet::Util::Windows::Error.new(_("Failed to logon user %{name}") % {name: name.inspect})
          end
        end

        yield token = token_pointer.read_handle
      end
    ensure
      FFI::WIN32.CloseHandle(token) if token
    end

    # token has been closed by this point
    true
  end
  module_function :logon_user

  def self.logon_user_by_logon_type(name, domain, password, logon_type, logon_provider, token)
    LogonUserW(wide_string(name), wide_string(domain), password.nil? ? FFI::Pointer::NULL : wide_string(password), logon_type, logon_provider, token)
  end

  private_class_method :logon_user_by_logon_type

  def load_profile(user, password)
    logon_user(user, password) do |token|
      FFI::MemoryPointer.from_string_to_wide_string(user) do |lpUserName|
        pi = PROFILEINFO.new
        pi[:dwSize] = PROFILEINFO.size
        pi[:dwFlags] = 1 # PI_NOUI - prevents display of profile error msgs
        pi[:lpUserName] = lpUserName

        # Load the profile. Since it doesn't exist, it will be created
        if LoadUserProfileW(token, pi.pointer) == FFI::WIN32_FALSE
          raise Puppet::Util::Windows::Error.new(_("Failed to load user profile %{user}") % { user: user.inspect })
        end

        Puppet.debug("Loaded profile for #{user}")

        if UnloadUserProfile(token, pi[:hProfile]) == FFI::WIN32_FALSE
          raise Puppet::Util::Windows::Error.new(_("Failed to unload user profile %{user}") % { user: user.inspect })
        end
      end
    end
  end
  module_function :load_profile

  def get_rights(name)
    user_info = Puppet::Util::Windows::SID.name_to_principal(name.sub(/^\.\\/, "#{Puppet::Util::Windows::ADSI.computer_name}\\"))
    return "" unless user_info

    rights = []
    rights_pointer = FFI::MemoryPointer.new(:pointer)
    number_of_rights = FFI::MemoryPointer.new(:ulong)
    sid_pointer = FFI::MemoryPointer.new(:byte, user_info.sid_bytes.length).write_array_of_uchar(user_info.sid_bytes)

    new_lsa_policy_handle do |policy_handle|
      result = LsaEnumerateAccountRights(policy_handle.read_pointer, sid_pointer, rights_pointer, number_of_rights)
      check_lsa_nt_status_and_raise_failures(result, "LsaEnumerateAccountRights")
    end

    number_of_rights.read_ulong.times do |index|
      right = LSA_UNICODE_STRING.new(rights_pointer.read_pointer + index * LSA_UNICODE_STRING.size)
      rights << right[:Buffer].read_arbitrary_wide_string_up_to
    end

    result = LsaFreeMemory(rights_pointer.read_pointer)
    check_lsa_nt_status_and_raise_failures(result, "LsaFreeMemory")

    rights.join(",")
  end
  module_function :get_rights

  def set_rights(name, rights)
    rights_pointer = new_lsa_unicode_strings_pointer(rights)
    user_info = Puppet::Util::Windows::SID.name_to_principal(name.sub(/^\.\\/, "#{Puppet::Util::Windows::ADSI.computer_name}\\"))
    sid_pointer = FFI::MemoryPointer.new(:byte, user_info.sid_bytes.length).write_array_of_uchar(user_info.sid_bytes)

    new_lsa_policy_handle do |policy_handle|
      result = LsaAddAccountRights(policy_handle.read_pointer, sid_pointer, rights_pointer, rights.size)
      check_lsa_nt_status_and_raise_failures(result, "LsaAddAccountRights")
    end
  end
  module_function :set_rights

  def remove_rights(name, rights)
    rights_pointer = new_lsa_unicode_strings_pointer(rights)
    user_info = Puppet::Util::Windows::SID.name_to_principal(name.sub(/^\.\\/, "#{Puppet::Util::Windows::ADSI.computer_name}\\"))
    sid_pointer = FFI::MemoryPointer.new(:byte, user_info.sid_bytes.length).write_array_of_uchar(user_info.sid_bytes)

    new_lsa_policy_handle do |policy_handle|
      result = LsaRemoveAccountRights(policy_handle.read_pointer, sid_pointer, false, rights_pointer, rights.size)
      check_lsa_nt_status_and_raise_failures(result, "LsaRemoveAccountRights")
    end
  end
  module_function :remove_rights

  def self.new_lsa_policy_handle
    access = 0
    access |= POLICY_LOOKUP_NAMES
    access |= POLICY_CREATE_ACCOUNT
    policy_handle = FFI::MemoryPointer.new(:pointer)

    result = LsaOpenPolicy(nil, LSA_OBJECT_ATTRIBUTES.new, access, policy_handle)
    check_lsa_nt_status_and_raise_failures(result, "LsaOpenPolicy")

    begin
      yield policy_handle
    ensure
      result = LsaClose(policy_handle.read_pointer)
      check_lsa_nt_status_and_raise_failures(result, "LsaClose")
    end
  end
  private_class_method :new_lsa_policy_handle

  def self.new_lsa_unicode_strings_pointer(strings)
    lsa_unicode_strings_pointer = FFI::MemoryPointer.new(LSA_UNICODE_STRING, strings.size)

    strings.each_with_index do |string, index|
      lsa_string = LSA_UNICODE_STRING.new(lsa_unicode_strings_pointer + index * LSA_UNICODE_STRING.size)
      lsa_string[:Buffer] = FFI::MemoryPointer.from_string(wide_string(string))
      lsa_string[:Length] = string.length * 2
      lsa_string[:MaximumLength] = lsa_string[:Length] + 2
    end

    lsa_unicode_strings_pointer
  end
  private_class_method :new_lsa_unicode_strings_pointer

  # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
  def self.check_lsa_nt_status_and_raise_failures(status, method_name)
    error_code = LsaNtStatusToWinError(status)

    error_reason = case error_code.to_s(16)
    when '0' # ERROR_SUCCESS
      return # Method call succeded
    when '2' # ERROR_FILE_NOT_FOUND
      return # No rights/privilleges assigned to given user
    when '5' # ERROR_ACCESS_DENIED
      "Access is denied. Please make sure that puppet is running as administrator."
    when '521' # ERROR_NO_SUCH_PRIVILEGE
      "One or more of the given rights/privilleges are incorrect."
    when '6ba' # RPC_S_SERVER_UNAVAILABLE
      "The RPC server is unavailable or given domain name is invalid."
    end

    raise Puppet::Error.new("Calling `#{method_name}` returned 'Win32 Error Code 0x%08X'. #{error_reason}" % error_code)
  end
  private_class_method :check_lsa_nt_status_and_raise_failures
end

# This class maps POSIX owner, group, and modes to the Windows
# security model, and back.
#
# The primary goal of this mapping is to ensure that owner, group, and
# modes can be round-tripped in a consistent and deterministic
# way. Otherwise, Puppet might think file resources are out-of-sync
# every time it runs. A secondary goal is to provide equivalent
# permissions for common use-cases. For example, setting the owner to
# "Administrators", group to "Users", and mode to 750 (which also
# denies access to everyone else.
#
# There are some well-known problems mapping windows and POSIX
# permissions due to differences between the two security
# models. Search for "POSIX permission mapping leak". In POSIX, access
# to a file is determined solely based on the most specific class
# (user, group, other). So a mode of 460 would deny write access to
# the owner even if they are a member of the group. But in Windows,
# the entire access control list is walked until the user is
# explicitly denied or allowed (denied take precedence, and if neither
# occurs they are denied). As a result, a user could be allowed access
# based on their group membership. To solve this problem, other people
# have used deny access control entries to more closely model POSIX,
# but this introduces a lot of complexity.
#
# In general, this implementation only supports "typical" permissions,
# where group permissions are a subset of user, and other permissions
# are a subset of group, e.g. 754, but not 467.  However, there are
# some Windows quirks to be aware of.
#
# * The owner can be either a user or group SID, and most system files
#   are owned by the Administrators group.
# * The group can be either a user or group SID.
# * Unexpected results can occur if the owner and group are the
#   same, but the user and group classes are different, e.g. 750. In
#   this case, it is not possible to allow write access to the owner,
#   but not the group. As a result, the actual permissions set on the
#   file would be 770.
# * In general, only privileged users can set the owner, group, or
#   change the mode for files they do not own. In 2003, the user must
#   be a member of the Administrators group. In Vista/2008, the user
#   must be running with elevated privileges.
# * A file/dir can be deleted by anyone with the DELETE access right
#   OR by anyone that has the FILE_DELETE_CHILD access right for the
#   parent. See https://support.microsoft.com/kb/238018. But on Unix,
#   the user must have write access to the file/dir AND execute access
#   to all of the parent path components.
# * Many access control entries are inherited from parent directories,
#   and it is common for file/dirs to have more than 3 entries,
#   e.g. Users, Power Users, Administrators, SYSTEM, etc, which cannot
#   be mapped into the 3 class POSIX model. The get_mode method will
#   set the S_IEXTRA bit flag indicating that an access control entry
#   was found whose SID is neither the owner, group, or other. This
#   enables Puppet to detect when file/dirs are out-of-sync,
#   especially those that Puppet did not create, but is attempting
#   to manage.
# * A special case of this is S_ISYSTEM_MISSING, which is set when the
#   SYSTEM permissions are *not* present on the DACL.
# * On Unix, the owner and group can be modified without changing the
#   mode. But on Windows, an access control entry specifies which SID
#   it applies to. As a result, the set_owner and set_group methods
#   automatically rebuild the access control list based on the new
#   (and different) owner or group.

require 'puppet/util/windows'
require 'pathname'

module Puppet::Util::Windows::Security
  include Puppet::Util::Windows::String

  include Puppet::FFI::Windows::Constants
  extend Puppet::FFI::Windows::Constants

  include Puppet::FFI::Windows::Structs
  extend Puppet::FFI::Windows::Structs

  include Puppet::FFI::Windows::Functions
  extend Puppet::FFI::Windows::Functions

  extend Puppet::Util::Windows::Security

  # Set the owner of the object referenced by +path+ to the specified
  # +owner_sid+.  The owner sid should be of the form "S-1-5-32-544"
  # and can either be a user or group.  Only a user with the
  # SE_RESTORE_NAME privilege in their process token can overwrite the
  # object's owner to something other than the current user.
  def set_owner(owner_sid, path)
    sd = get_security_descriptor(path)

    if owner_sid != sd.owner
      sd.owner = owner_sid
      set_security_descriptor(path, sd)
    end
  end

  # Get the owner of the object referenced by +path+.  The returned
  # value is a SID string, e.g. "S-1-5-32-544".  Any user with read
  # access to an object can get the owner. Only a user with the
  # SE_BACKUP_NAME privilege in their process token can get the owner
  # for objects they do not have read access to.
  def get_owner(path)
    return unless supports_acl?(path)

    get_security_descriptor(path).owner
  end

  # Set the owner of the object referenced by +path+ to the specified
  # +group_sid+.  The group sid should be of the form "S-1-5-32-544"
  # and can either be a user or group.  Any user with WRITE_OWNER
  # access to the object can change the group (regardless of whether
  # the current user belongs to that group or not).
  def set_group(group_sid, path)
    sd = get_security_descriptor(path)

    if group_sid != sd.group
      sd.group = group_sid
      set_security_descriptor(path, sd)
    end
  end

  # Get the group of the object referenced by +path+.  The returned
  # value is a SID string, e.g. "S-1-5-32-544".  Any user with read
  # access to an object can get the group. Only a user with the
  # SE_BACKUP_NAME privilege in their process token can get the group
  # for objects they do not have read access to.
  def get_group(path)
    return unless supports_acl?(path)

    get_security_descriptor(path).group
  end

  def supports_acl?(path)
    supported = false
    root = Pathname.new(path).enum_for(:ascend).to_a.last.to_s
    # 'A trailing backslash is required'
    root = "#{root}\\" unless root =~ /[\/\\]$/

    FFI::MemoryPointer.new(:pointer, 1) do |flags_ptr|
      if GetVolumeInformationW(wide_string(root), FFI::Pointer::NULL, 0,
          FFI::Pointer::NULL, FFI::Pointer::NULL,
          flags_ptr, FFI::Pointer::NULL, 0) == FFI::WIN32_FALSE
        raise Puppet::Util::Windows::Error.new(_("Failed to get volume information"))
      end
      supported = flags_ptr.read_dword & FILE_PERSISTENT_ACLS == FILE_PERSISTENT_ACLS
    end

    supported
  end

  def get_aces_for_path_by_sid(path, sid)
    get_security_descriptor(path).dacl.select { |ace| ace.sid == sid }
  end

  # Get the mode of the object referenced by +path+.  The returned
  # integer value represents the POSIX-style read, write, and execute
  # modes for the user, group, and other classes, e.g. 0640.  Any user
  # with read access to an object can get the mode. Only a user with
  # the SE_BACKUP_NAME privilege in their process token can get the
  # mode for objects they do not have read access to.
  def get_mode(path)
    return unless supports_acl?(path)

    well_known_world_sid = Puppet::Util::Windows::SID::Everyone
    well_known_nobody_sid = Puppet::Util::Windows::SID::Nobody
    well_known_system_sid = Puppet::Util::Windows::SID::LocalSystem
    well_known_app_packages_sid = Puppet::Util::Windows::SID::AllAppPackages

    mode = S_ISYSTEM_MISSING

    sd = get_security_descriptor(path)
    sd.dacl.each do |ace|
      next if ace.inherit_only?

      case ace.sid
      when sd.owner
        MASK_TO_MODE.each_pair do |k,v|
          if (ace.mask & k) == k
            mode |= (v << 6)
          end
        end
      when sd.group
        MASK_TO_MODE.each_pair do |k,v|
          if (ace.mask & k) == k
            mode |= (v << 3)
          end
        end
      when well_known_world_sid
        MASK_TO_MODE.each_pair do |k,v|
          if (ace.mask & k) == k
            mode |= (v << 6) | (v << 3) | v
          end
        end
        if File.directory?(path) &&
          (ace.mask & (FILE_WRITE_DATA | FILE_EXECUTE | FILE_DELETE_CHILD)) == (FILE_WRITE_DATA | FILE_EXECUTE)
          mode |= S_ISVTX;
        end
      when well_known_nobody_sid
        if (ace.mask & FILE_APPEND_DATA).nonzero?
          mode |= S_ISVTX
        end
      when well_known_app_packages_sid
      when well_known_system_sid
      else
        #puts "Warning, unable to map SID into POSIX mode: #{ace.sid}"
        mode |= S_IEXTRA
      end

      if ace.sid == well_known_system_sid
        mode &= ~S_ISYSTEM_MISSING
      end

      # if owner and group the same, then user and group modes are the OR of both
      if sd.owner == sd.group
        mode |= ((mode & S_IRWXG) << 3) | ((mode & S_IRWXU) >> 3)
        #puts "owner: #{sd.group}, 0x#{ace.mask.to_s(16)}, #{mode.to_s(8)}"
      end
    end

    #puts "get_mode: #{mode.to_s(8)}"
    mode
  end

  MODE_TO_MASK = {
    S_IROTH => FILE_GENERIC_READ,
    S_IWOTH => FILE_GENERIC_WRITE,
    S_IXOTH => (FILE_GENERIC_EXECUTE & ~FILE_READ_ATTRIBUTES),
  }

  # Set the mode of the object referenced by +path+ to the specified
  # +mode+. The mode should be specified as POSIX-style read, write,
  # and execute modes for the user, group, and other classes,
  # e.g. 0640. The sticky bit, S_ISVTX, is supported, but is only
  # meaningful for directories. If set, group and others are not
  # allowed to delete child objects for which they are not the owner.
  # By default, the DACL is set to protected, meaning it does not
  # inherit access control entries from parent objects. This can be
  # changed by setting +protected+ to false. The owner of the object
  # (with READ_CONTROL and WRITE_DACL access) can always change the
  # mode. Only a user with the SE_BACKUP_NAME and SE_RESTORE_NAME
  # privileges in their process token can change the mode for objects
  # that they do not have read and write access to.
  def set_mode(mode, path, protected = true, managing_owner = false, managing_group = false)
    sd = get_security_descriptor(path)
    well_known_world_sid = Puppet::Util::Windows::SID::Everyone
    well_known_nobody_sid = Puppet::Util::Windows::SID::Nobody
    well_known_system_sid = Puppet::Util::Windows::SID::LocalSystem

    owner_allow = STANDARD_RIGHTS_ALL  |
      FILE_READ_ATTRIBUTES |
      FILE_WRITE_ATTRIBUTES
    # this prevents a mode that is not 7 from taking ownership of a file based
    # on group membership and rewriting it / making it executable
    group_allow = STANDARD_RIGHTS_READ |
      FILE_READ_ATTRIBUTES |
      SYNCHRONIZE
    other_allow = STANDARD_RIGHTS_READ |
      FILE_READ_ATTRIBUTES |
      SYNCHRONIZE
    nobody_allow = 0
    system_allow = 0

    MODE_TO_MASK.each do |k,v|
      if ((mode >> 6) & k) == k
        owner_allow |= v
      end
      if ((mode >> 3) & k) == k
        group_allow |= v
      end
      if (mode & k) == k
        other_allow |= v
      end
    end

    # With a mode value of '7' for group / other, the value must then include
    # additional perms beyond STANDARD_RIGHTS_READ to allow DACL modification
    if ((mode & S_IRWXG) == S_IRWXG)
      group_allow |= DELETE | WRITE_DAC | WRITE_OWNER
    end
    if ((mode & S_IRWXO) == S_IRWXO)
      other_allow |= DELETE | WRITE_DAC | WRITE_OWNER
    end

    if (mode & S_ISVTX).nonzero?
      nobody_allow |= FILE_APPEND_DATA;
    end

    isownergroup = sd.owner == sd.group

    # caller is NOT managing SYSTEM by using group or owner, so set to FULL
    if ! [sd.owner, sd.group].include? well_known_system_sid
      # we don't check S_ISYSTEM_MISSING bit, but automatically carry over existing SYSTEM perms
      # by default set SYSTEM perms to full
      system_allow = FILE_ALL_ACCESS
    else
      # It is possible to set SYSTEM with a mode other than Full Control (7) however this makes no sense and in practical terms
      # should not be done.  We can trap these instances and correct them before being applied.
      if (sd.owner == well_known_system_sid) && (owner_allow != FILE_ALL_ACCESS)
        # If owner and group are both SYSTEM but group is unmanaged the control rights of system will be set to FullControl by
        # the unmanaged group, so there is no need for the warning
        if managing_owner && (!isownergroup || managing_group)
          #TRANSLATORS 'SYSTEM' is a Windows name and should not be translated
          Puppet.warning _("Setting control rights for %{path} owner SYSTEM to less than Full Control rights. Setting SYSTEM rights to less than Full Control may have unintented consequences for operations on this file") % { path: path }
        elsif managing_owner && isownergroup
          #TRANSLATORS 'SYSTEM' is a Windows name and should not be translated
          Puppet.debug { _("%{path} owner and group both set to user SYSTEM, but group is not managed directly: SYSTEM user rights will be set to FullControl by group") % { path: path } }
        else
          #TRANSLATORS 'SYSTEM' is a Windows name and should not be translated
          Puppet.debug { _("An attempt to set mode %{mode} on item %{path} would result in the owner, SYSTEM, to have less than Full Control rights. This attempt has been corrected to Full Control") % { mode: mode.to_s(8), path: path } }
          owner_allow = FILE_ALL_ACCESS
        end
      end

      if (sd.group == well_known_system_sid) && (group_allow != FILE_ALL_ACCESS)
        # If owner and group are both SYSTEM but owner is unmanaged the control rights of system will be set to FullControl by
        # the unmanaged owner, so there is no need for the warning.
        if managing_group && (!isownergroup || managing_owner)
          #TRANSLATORS 'SYSTEM' is a Windows name and should not be translated
          Puppet.warning _("Setting control rights for %{path} group SYSTEM to less than Full Control rights. Setting SYSTEM rights to less than Full Control may have unintented consequences for operations on this file") % { path: path }
        elsif managing_group && isownergroup
          #TRANSLATORS 'SYSTEM' is a Windows name and should not be translated
          Puppet.debug { _("%{path} owner and group both set to user SYSTEM, but owner is not managed directly: SYSTEM user rights will be set to FullControl by owner") % { path: path } }
        else
          #TRANSLATORS 'SYSTEM' is a Windows name and should not be translated
          Puppet.debug { _("An attempt to set mode %{mode} on item %{path} would result in the group, SYSTEM, to have less than Full Control rights. This attempt has been corrected to Full Control") % { mode: mode.to_s(8), path: path } }
          group_allow = FILE_ALL_ACCESS
        end
      end
    end

    # even though FILE_DELETE_CHILD only applies to directories, it can be set on files
    # this is necessary to do to ensure a file ends up with (F) FullControl
    if (mode & (S_IWUSR | S_IXUSR)) == (S_IWUSR | S_IXUSR)
      owner_allow |= FILE_DELETE_CHILD
    end
    if (mode & (S_IWGRP | S_IXGRP)) == (S_IWGRP | S_IXGRP) && (mode & S_ISVTX) == 0
      group_allow |= FILE_DELETE_CHILD
    end
    if (mode & (S_IWOTH | S_IXOTH)) == (S_IWOTH | S_IXOTH) && (mode & S_ISVTX) == 0
      other_allow |= FILE_DELETE_CHILD
    end

    # if owner and group the same, then map group permissions to the one owner ACE
    if isownergroup
      owner_allow |= group_allow
    end

    # if any ACE allows write, then clear readonly bit, but do this before we overwrite
    # the DACl and lose our ability to set the attribute
    if ((owner_allow | group_allow | other_allow ) & FILE_WRITE_DATA) == FILE_WRITE_DATA
      Puppet::Util::Windows::File.remove_attributes(path, FILE_ATTRIBUTE_READONLY)
    end

    isdir = File.directory?(path)
    dacl = Puppet::Util::Windows::AccessControlList.new
    dacl.allow(sd.owner, owner_allow)
    unless isownergroup
      dacl.allow(sd.group, group_allow)
    end
    dacl.allow(well_known_world_sid, other_allow)
    dacl.allow(well_known_nobody_sid, nobody_allow)

    # TODO: system should be first?
    flags = !isdir ? 0 :
      Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE |
      Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE
    dacl.allow(well_known_system_sid, system_allow, flags)

    # add inherit-only aces for child dirs and files that are created within the dir
    inherit_only = Puppet::Util::Windows::AccessControlEntry::INHERIT_ONLY_ACE
    if isdir
      inherit = inherit_only | Puppet::Util::Windows::AccessControlEntry::CONTAINER_INHERIT_ACE
      dacl.allow(Puppet::Util::Windows::SID::CreatorOwner, owner_allow, inherit)
      dacl.allow(Puppet::Util::Windows::SID::CreatorGroup, group_allow, inherit)

      inherit = inherit_only | Puppet::Util::Windows::AccessControlEntry::OBJECT_INHERIT_ACE
      # allow any previously set bits *except* for these
      perms_to_strip = ~(FILE_EXECUTE + WRITE_OWNER + WRITE_DAC)
      dacl.allow(Puppet::Util::Windows::SID::CreatorOwner, owner_allow & perms_to_strip, inherit)
      dacl.allow(Puppet::Util::Windows::SID::CreatorGroup, group_allow & perms_to_strip, inherit)
    end

    new_sd = Puppet::Util::Windows::SecurityDescriptor.new(sd.owner, sd.group, dacl, protected)
    set_security_descriptor(path, new_sd)

    nil
  end

  ACL_REVISION                   = 2

  def add_access_allowed_ace(acl, mask, sid, inherit = nil)
    inherit ||= NO_INHERITANCE

    Puppet::Util::Windows::SID.string_to_sid_ptr(sid) do |sid_ptr|
      if Puppet::Util::Windows::SID.IsValidSid(sid_ptr) == FFI::WIN32_FALSE
        raise Puppet::Util::Windows::Error.new(_("Invalid SID"))
      end

      if AddAccessAllowedAceEx(acl, ACL_REVISION, inherit, mask, sid_ptr) == FFI::WIN32_FALSE
        raise Puppet::Util::Windows::Error.new(_("Failed to add access control entry"))
      end
    end

    # ensure this method is void if it doesn't raise
    nil
  end

  def add_access_denied_ace(acl, mask, sid, inherit = nil)
    inherit ||= NO_INHERITANCE

    Puppet::Util::Windows::SID.string_to_sid_ptr(sid) do |sid_ptr|
      if Puppet::Util::Windows::SID.IsValidSid(sid_ptr) == FFI::WIN32_FALSE
        raise Puppet::Util::Windows::Error.new(_("Invalid SID"))
      end

      if AddAccessDeniedAceEx(acl, ACL_REVISION, inherit, mask, sid_ptr) == FFI::WIN32_FALSE
        raise Puppet::Util::Windows::Error.new(_("Failed to add access control entry"))
      end
    end

    # ensure this method is void if it doesn't raise
    nil
  end

  def parse_dacl(dacl_ptr)
    # REMIND: need to handle NULL DACL
    if IsValidAcl(dacl_ptr) == FFI::WIN32_FALSE
      raise Puppet::Util::Windows::Error.new(_("Invalid DACL"))
    end

    dacl_struct = ACL.new(dacl_ptr)
    ace_count = dacl_struct[:AceCount]

    dacl = Puppet::Util::Windows::AccessControlList.new

    # deny all
    return dacl if ace_count == 0

    0.upto(ace_count - 1) do |i|
      FFI::MemoryPointer.new(:pointer, 1) do |ace_ptr|

        next if GetAce(dacl_ptr, i, ace_ptr) == FFI::WIN32_FALSE

        # ACE structures vary depending on the type. We are only concerned with
        # ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACEs, which have the same layout
        ace = GENERIC_ACCESS_ACE.new(ace_ptr.get_pointer(0)) #deref LPVOID *

        ace_type = ace[:Header][:AceType]
        if ace_type != Puppet::Util::Windows::AccessControlEntry::ACCESS_ALLOWED_ACE_TYPE &&
          ace_type != Puppet::Util::Windows::AccessControlEntry::ACCESS_DENIED_ACE_TYPE
          Puppet.warning _("Unsupported access control entry type: 0x%{type}") % { type: ace_type.to_s(16) }
          next
        end

        # using pointer addition gives the FFI::Pointer a size, but that's OK here
        sid = Puppet::Util::Windows::SID.sid_ptr_to_string(ace.pointer + GENERIC_ACCESS_ACE.offset_of(:SidStart))
        mask = ace[:Mask]
        ace_flags = ace[:Header][:AceFlags]

        case ace_type
        when Puppet::Util::Windows::AccessControlEntry::ACCESS_ALLOWED_ACE_TYPE
          dacl.allow(sid, mask, ace_flags)
        when Puppet::Util::Windows::AccessControlEntry::ACCESS_DENIED_ACE_TYPE
          dacl.deny(sid, mask, ace_flags)
        end
      end
    end

    dacl
  end

  # Open an existing file with the specified access mode, and execute a
  # block with the opened file HANDLE.
  def open_file(path, access, &block)
    handle = CreateFileW(
             wide_string(path),
             access,
             FILE_SHARE_READ | FILE_SHARE_WRITE,
             FFI::Pointer::NULL, # security_attributes
             OPEN_EXISTING,
             FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
             FFI::Pointer::NULL_HANDLE) # template

    if handle == Puppet::Util::Windows::File::INVALID_HANDLE_VALUE
      raise Puppet::Util::Windows::Error.new(_("Failed to open '%{path}'") % { path: path })
    end

    begin
      yield handle
    ensure
      FFI::WIN32.CloseHandle(handle) if handle
    end

    # handle has already had CloseHandle called against it, nothing to return
    nil
  end

  # Execute a block with the specified privilege enabled
  def with_privilege(privilege, &block)
    set_privilege(privilege, true)
    yield
  ensure
    set_privilege(privilege, false)
  end

  SE_PRIVILEGE_ENABLED    = 0x00000002
  TOKEN_ADJUST_PRIVILEGES = 0x0020

  # Enable or disable a privilege. Note this doesn't add any privileges the
  # user doesn't already has, it just enables privileges that are disabled.
  def set_privilege(privilege, enable)
    return unless Puppet.features.root?

    Puppet::Util::Windows::Process.with_process_token(TOKEN_ADJUST_PRIVILEGES) do |token|
      Puppet::Util::Windows::Process.lookup_privilege_value(privilege) do |luid|
        FFI::MemoryPointer.new(Puppet::Util::Windows::Process::LUID_AND_ATTRIBUTES.size) do |luid_and_attributes_ptr|
          # allocate unmanaged memory for structs that we clean up afterwards
          luid_and_attributes = Puppet::Util::Windows::Process::LUID_AND_ATTRIBUTES.new(luid_and_attributes_ptr)
          luid_and_attributes[:Luid] = luid
          luid_and_attributes[:Attributes] = enable ? SE_PRIVILEGE_ENABLED : 0

          FFI::MemoryPointer.new(Puppet::Util::Windows::Process::TOKEN_PRIVILEGES.size) do |token_privileges_ptr|
            token_privileges = Puppet::Util::Windows::Process::TOKEN_PRIVILEGES.new(token_privileges_ptr)
            token_privileges[:PrivilegeCount] = 1
            token_privileges[:Privileges][0] = luid_and_attributes

            # size is correct given we only have 1 LUID, otherwise would be:
            # [:PrivilegeCount].size + [:PrivilegeCount] * LUID_AND_ATTRIBUTES.size
            if AdjustTokenPrivileges(token, FFI::WIN32_FALSE,
                token_privileges, token_privileges.size,
                FFI::MemoryPointer::NULL, FFI::MemoryPointer::NULL) == FFI::WIN32_FALSE
              raise Puppet::Util::Windows::Error.new(_("Failed to adjust process privileges"))
            end
          end
        end
      end
    end

    # token / luid structs freed by this point, so return true as nothing raised
    true
  end

  def get_security_descriptor(path)
    sd = nil

    with_privilege(SE_BACKUP_NAME) do
      open_file(path, READ_CONTROL) do |handle|
        FFI::MemoryPointer.new(:pointer, 1) do |owner_sid_ptr_ptr|
          FFI::MemoryPointer.new(:pointer, 1) do |group_sid_ptr_ptr|
            FFI::MemoryPointer.new(:pointer, 1) do |dacl_ptr_ptr|
              FFI::MemoryPointer.new(:pointer, 1) do |sd_ptr_ptr|

                rv = GetSecurityInfo(
                  handle,
                  :SE_FILE_OBJECT,
                  OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                  owner_sid_ptr_ptr,
                  group_sid_ptr_ptr,
                  dacl_ptr_ptr,
                  FFI::Pointer::NULL, #sacl
                  sd_ptr_ptr) #sec desc
                raise Puppet::Util::Windows::Error.new(_("Failed to get security information")) if rv != FFI::ERROR_SUCCESS

                # these 2 convenience params are not freed since they point inside sd_ptr
                owner = Puppet::Util::Windows::SID.sid_ptr_to_string(owner_sid_ptr_ptr.get_pointer(0))
                group = Puppet::Util::Windows::SID.sid_ptr_to_string(group_sid_ptr_ptr.get_pointer(0))

                FFI::MemoryPointer.new(:word, 1) do |control|
                  FFI::MemoryPointer.new(:dword, 1) do |revision|
                    sd_ptr_ptr.read_win32_local_pointer do |sd_ptr|

                      if GetSecurityDescriptorControl(sd_ptr, control, revision) == FFI::WIN32_FALSE
                        raise Puppet::Util::Windows::Error.new(_("Failed to get security descriptor control"))
                      end

                      protect = (control.read_word & SE_DACL_PROTECTED) == SE_DACL_PROTECTED
                      dacl = parse_dacl(dacl_ptr_ptr.get_pointer(0))
                      sd = Puppet::Util::Windows::SecurityDescriptor.new(owner, group, dacl, protect)
                    end
                  end
                end
              end
            end
          end
        end
      end
    end

    sd
  end

  def get_max_generic_acl_size(ace_count)
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa378853(v=vs.85).aspx
    # To calculate the initial size of an ACL, add the following together, and then align the result to the nearest DWORD:
    # * Size of the ACL structure.
    # * Size of each ACE structure that the ACL is to contain minus the SidStart member (DWORD) of the ACE.
    # * Length of the SID that each ACE is to contain.
    ACL.size + ace_count * MAXIMUM_GENERIC_ACE_SIZE
  end

  # setting DACL requires both READ_CONTROL and WRITE_DACL access rights,
  # and their respective privileges, SE_BACKUP_NAME and SE_RESTORE_NAME.
  def set_security_descriptor(path, sd)
    FFI::MemoryPointer.new(:byte, get_max_generic_acl_size(sd.dacl.count)) do |acl_ptr|
      if InitializeAcl(acl_ptr, acl_ptr.size, ACL_REVISION) == FFI::WIN32_FALSE
        raise Puppet::Util::Windows::Error.new(_("Failed to initialize ACL"))
      end

      if IsValidAcl(acl_ptr) == FFI::WIN32_FALSE
        raise Puppet::Util::Windows::Error.new(_("Invalid DACL"))
      end

      with_privilege(SE_BACKUP_NAME) do
        with_privilege(SE_RESTORE_NAME) do
          open_file(path, READ_CONTROL | WRITE_DAC | WRITE_OWNER) do |handle|
            Puppet::Util::Windows::SID.string_to_sid_ptr(sd.owner) do |owner_sid_ptr|
              Puppet::Util::Windows::SID.string_to_sid_ptr(sd.group) do |group_sid_ptr|
                sd.dacl.each do |ace|
                  case ace.type
                  when Puppet::Util::Windows::AccessControlEntry::ACCESS_ALLOWED_ACE_TYPE
                    #puts "ace: allow, sid #{Puppet::Util::Windows::SID.sid_to_name(ace.sid)}, mask 0x#{ace.mask.to_s(16)}"
                    add_access_allowed_ace(acl_ptr, ace.mask, ace.sid, ace.flags)
                  when Puppet::Util::Windows::AccessControlEntry::ACCESS_DENIED_ACE_TYPE
                    #puts "ace: deny, sid #{Puppet::Util::Windows::SID.sid_to_name(ace.sid)}, mask 0x#{ace.mask.to_s(16)}"
                    add_access_denied_ace(acl_ptr, ace.mask, ace.sid, ace.flags)
                  else
                    raise "We should never get here"
                    # TODO: this should have been a warning in an earlier commit
                  end
                end

                # protected means the object does not inherit aces from its parent
                flags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
                flags |= sd.protect ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION

                rv = SetSecurityInfo(handle,
                                     :SE_FILE_OBJECT,
                                     flags,
                                     owner_sid_ptr,
                                     group_sid_ptr,
                                     acl_ptr,
                                     FFI::MemoryPointer::NULL)

                if rv != FFI::ERROR_SUCCESS
                  raise Puppet::Util::Windows::Error.new(_("Failed to set security information"))
                end
              end
            end
          end
        end
      end
    end
  end
end

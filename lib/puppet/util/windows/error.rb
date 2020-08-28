require 'puppet/util/windows'
require 'puppet/error'

# represents an error resulting from a Win32 error code
class Puppet::Util::Windows::Error < Puppet::Error
  extend Puppet::FFI::Windows::Functions
  extend Puppet::FFI::Windows::Constants

  attr_reader :code

  # NOTE: FFI.errno only works properly when prior Win32 calls have been made
  # through FFI bindings.  Calls made through Win32API do not have their error
  # codes captured by FFI.errno
  def initialize(message, code = FFI.errno, original = nil)
    super(message + ":  #{self.class.format_error_code(code)}", original)

    @code = code
  end

  # Helper method that wraps FormatMessage that returns a human readable string.
  def self.format_error_code(code)
    # specifying 0 will look for LANGID in the following order
    # 1.Language neutral
    # 2.Thread LANGID, based on the thread's locale value
    # 3.User default LANGID, based on the user's default locale value
    # 4.System default LANGID, based on the system default locale value
    # 5.US English
    dwLanguageId = 0
    flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_ARGUMENT_ARRAY |
            FORMAT_MESSAGE_IGNORE_INSERTS |
            FORMAT_MESSAGE_MAX_WIDTH_MASK
    error_string = ''

    # this pointer actually points to a :lpwstr (pointer) since we're letting Windows allocate for us
    FFI::MemoryPointer.new(:pointer, 1) do |buffer_ptr|
      length = FormatMessageW(flags, FFI::Pointer::NULL, code, dwLanguageId,
        buffer_ptr, 0, FFI::Pointer::NULL)

      if length == FFI::WIN32_FALSE
        # can't raise same error type here or potentially recurse infinitely
        raise Puppet::Error.new(_("FormatMessageW could not format code %{code}") % { code: code })
      end

      # returns an FFI::Pointer with autorelease set to false, which is what we want
      buffer_ptr.read_win32_local_pointer do |wide_string_ptr|
        if wide_string_ptr.null?
          raise Puppet::Error.new(_("FormatMessageW failed to allocate buffer for code %{code}") % { code: code })
        end

        error_string = wide_string_ptr.read_wide_string(length)
      end
    end

    error_string
  end
end

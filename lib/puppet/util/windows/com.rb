require 'puppet/util/windows'

module Puppet::Util::Windows::COM
  extend Puppet::FFI::Windows::Functions

  def SUCCEEDED(hr) hr >= 0 end
  def FAILED(hr) hr < 0 end

  module_function :SUCCEEDED, :FAILED

  def raise_if_hresult_failed(name, *args)
    failed = FAILED(result = send(name, *args)) and raise _("%{name} failed (hresult %{result}).") % { name: name, result: format('%#08x', result) }

    result
  ensure
    yield failed if block_given?
  end

  module_function :raise_if_hresult_failed

  # code modified from Unknownr project https://github.com/rpeev/Unknownr
  # licensed under MIT
  module Interface
    def self.[](*args)
      spec, iid, *ifaces = args.reverse

      spec.each { |name, signature| signature[0].unshift(:pointer) }

      Class.new(FFI::Struct) do
        const_set(:IID, iid)

        vtable = Class.new(FFI::Struct) do
          vtable_hash = Hash[(ifaces.map { |iface| iface::VTBL::SPEC.to_a } << spec.to_a).flatten(1)]
          const_set(:SPEC, vtable_hash)

          layout(
            *self::SPEC.map { |name, signature| [name, callback(*signature)] }.flatten
          )
        end

        const_set(:VTBL, vtable)

        layout \
          :lpVtbl, :pointer
      end
    end
  end

  module Helpers
    def QueryInstance(klass)
      instance = nil

      FFI::MemoryPointer.new(:pointer) do |ppv|
        QueryInterface(klass::IID, ppv)

        instance = klass.new(ppv.read_pointer)
      end

      begin
        yield instance
        return self
      ensure
        instance.Release
      end if block_given?

      instance
    end

    def UseInstance(klass, name, *args)
      instance = nil

      FFI::MemoryPointer.new(:pointer) do |ppv|
        send(name, *args, ppv)

        yield instance = klass.new(ppv.read_pointer)
      end

      self
    ensure
      instance.Release if instance && ! instance.null?
    end
  end

  module Instance
    def self.[](iface)
      Class.new(iface) do
        send(:include, Helpers)

        def initialize(pointer)
          self.pointer = pointer

          @vtbl = self.class::VTBL.new(self[:lpVtbl])
        end

        attr_reader :vtbl

        self::VTBL.members.each do |name|
          define_method(name) do |*args|
            if Puppet::Util::Windows::COM.FAILED(result = @vtbl[name].call(self, *args))
              raise Puppet::Util::Windows::Error.new(_("Failed to call %{klass}::%{name} with HRESULT: %{result}.") % { klass: self, name: name, result: result }, result)
            end
            result
          end
        end

        layout \
          :lpVtbl, :pointer
      end
    end
  end

  module Factory
    extend Puppet::FFI::Windows::Functions
    extend Puppet::FFI::Windows::Constants

    def self.[](iface, clsid)
      Class.new(iface) do
        send(:include, Helpers)

        const_set(:CLSID, clsid)

        def initialize(opts = {})
          @opts = opts

          @opts[:clsctx] ||= CLSCTX_INPROC_SERVER

          FFI::MemoryPointer.new(:pointer) do |ppv|
            hr = CoCreateInstance(self.class::CLSID, FFI::Pointer::NULL, @opts[:clsctx], self.class::IID, ppv)
            if Puppet::Util::Windows::COM.FAILED(hr)
              raise _("CoCreateInstance failed (%{klass}).") % { klass: self.class }
            end

            self.pointer = ppv.read_pointer
          end

          @vtbl = self.class::VTBL.new(self[:lpVtbl])
        end

        attr_reader :vtbl

        self::VTBL.members.each do |name|
          define_method(name) do |*args|
            if Puppet::Util::Windows::COM.FAILED(result = @vtbl[name].call(self, *args))
              raise Puppet::Util::Windows::Error.new(_("Failed to call %{klass}::%{name} with HRESULT: %{result}.") % { klass: self, name: name, result: result }, result)
            end
            result
          end
        end

        layout \
          :lpVtbl, :pointer
      end
    end
  end

  IUnknown = Interface[
    FFI::WIN32::GUID['00000000-0000-0000-C000-000000000046'],

    QueryInterface: [[:pointer, :pointer], :hresult],
    AddRef: [[], :win32_ulong],
    Release: [[], :win32_ulong]
  ]

  Unknown = Instance[IUnknown]

  def InitializeCom
    raise_if_hresult_failed(:CoInitialize, FFI::Pointer::NULL)

    at_exit { CoUninitialize() }
  end
  module_function :InitializeCom
end

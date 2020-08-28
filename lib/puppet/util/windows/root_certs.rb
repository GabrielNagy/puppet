require 'puppet/util/windows'
require 'puppet/ssl/openssl_loader'

# Represents a collection of trusted root certificates.
#
# @api public
class Puppet::Util::Windows::RootCerts
  extend Puppet::FFI::Windows::Functions
  extend Puppet::FFI::Windows::Structs

  include Enumerable

  def initialize(roots)
    @roots = roots
  end

  # Enumerates each root certificate.
  # @yieldparam cert [OpenSSL::X509::Certificate] each root certificate
  # @api public
  def each
    @roots.each {|cert| yield cert}
  end

  # Returns a new instance.
  # @return [Puppet::Util::Windows::RootCerts] object constructed from current root certificates
  def self.instance
    new(self.load_certs)
  end

  # Returns an array of root certificates.
  #
  # @return [Array<[OpenSSL::X509::Certificate]>] an array of root certificates
  # @api private
  def self.load_certs
    certs = []

    # This is based on a patch submitted to openssl:
    # https://www.mail-archive.com/openssl-dev@openssl.org/msg26958.html
    ptr = FFI::Pointer::NULL
    store = CertOpenSystemStoreA(nil, "ROOT")
    begin
      while (ptr = CertEnumCertificatesInStore(store, ptr)) and not ptr.null?
        context = CERT_CONTEXT.new(ptr)
        cert_buf = context[:pbCertEncoded].read_bytes(context[:cbCertEncoded])
        begin
          certs << OpenSSL::X509::Certificate.new(cert_buf)
        rescue => detail
          Puppet.warning(_("Failed to import root certificate: %{detail}") % { detail: detail.inspect })
        end
      end
    ensure
      CertCloseStore(store, 0)
    end

    certs
  end
end

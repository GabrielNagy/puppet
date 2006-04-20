if __FILE__ == $0
    $:.unshift '../../lib'
    $:.unshift '..'
    $puppetbase = "../.."
end

require 'puppet'
require 'puppet/server/pelement'
require 'test/unit'
require 'puppettest.rb'
require 'base64'
require 'cgi'

class TestPElementServer < Test::Unit::TestCase
	include ServerTest

    def test_describe_file
        # Make a file to describe
        file = tempfile()
        str = "yayness\n"

        server = nil

        assert_nothing_raised do
            server = Puppet::Server::PElementServer.new()
        end

        [   [nil],
            [[:content, :mode], []],
            [[], [:content]],
            [[:content], [:mode]]
        ].each do |ary|
            retrieve = ary[0] || []
            ignore = ary[1] || []

            File.open(file, "w") { |f| f.print str }

            result = nil
            assert_nothing_raised do
                result = server.describe("file", file, *ary)
            end

            assert(result, "Could not retrieve file information")

            assert_instance_of(Puppet::TransObject, result)

            # Now we have to clear, so that the server's object gets removed
            Puppet::Type.type(:file).clear

            # And remove the file, so we can verify it gets recreated
            File.unlink(file)

            object = nil
            assert_nothing_raised do
                object = result.to_type
            end

            assert(object, "Could not create type")

            retrieve.each do |state|
                assert(object.should(state), "Did not retrieve %s" % state)
            end

            ignore.each do |state|
                assert(! object.should(state), "Incorrectly retrieved %s" % state)
            end

            assert_events([:file_created], object)

            assert(FileTest.exists?(file), "File did not get recreated")

            if object.should(:content)
                assert_equal(str, File.read(file), "File contents are not the same")
            else
                assert_equal("", File.read(file), "File content was incorrectly made")
            end
        end
    end
end

# $Id$

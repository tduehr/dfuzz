#!/usr/bin/env ruby
#
# = fuzz.rb
#
# Fuzz Generators
#
# Ruby 1.8 Generators use continuations (which are slow) and leak
# memory like crazy, so use generators.rb from Ruby 1.9.
#
# Author:: Dai Zovi, Dino <ddz@theta44.org>
# License:: Private
# Revision:: $Id$
#

if RUBY_VERSION < "1.9"
  require 'dfuzz/generator18'
else
  require 'dfuzz/generator'
end

require 'dfuzz/fudge'
require 'dfuzz/integer'
require 'dfuzz/char'
require 'dfuzz/block'
require 'dfuzz/sequential'
require 'dfuzz/string'
require 'dfuzz/Diagonal'

module DFuzz
  #
  # Modules for higher-level tokens (e-mail addresses, asn1, etc)
  #
  class EmailAddress < Generator
    def initialize()
    end
  end

end

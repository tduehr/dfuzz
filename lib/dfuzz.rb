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
module DFuzz
  if RUBY_VERSION < "1.9"
    require 'dfuzz/generator'
  else
    class Generator < ::Enumerator
      def next?
        begin
          self.peek
          true
        rescue StopIteration
          false
        end
      end

      # def to_a; self; end
      def shift; next? ? self.next : nil; end
      def empty?; !self.next?; end
    end
  end
end

module DFuzz
    # Generate Xi-F...Xi+F for each Xi in boundaries and fudge_factor F
    class Fudge < DFuzz::Generator
        def initialize(boundaries, fudge_factor, mask = nil)
            super() { |g|
                boundaries.each {|b|
                    0.upto(fudge_factor) { |f|
                        if (mask)
                            g.yield((b+f) & mask)
                            g.yield((b-f) & mask)
                        else
                            g.yield b+f
                            g.yield b-f
                        end
                    }
                }
            }
        end
    end

    # Serially generate each variable in turn (equivalent to
    # recursively nesting generators)
    class Block
        def initialize(defaults, generators)
            @defaults = defaults
            @generators = generators
        end

        def run(&block)
            generators_index = 0

            # Baseline
            block.call(@defaults)

            # Iterate through generators, fully exhausting each and
            # calling the code block with each set of values
            @generators.each { |g|
                values = Array.new(@defaults)
                while (g.next?)
                    values[generators_index] = g.next
                    block.call(values)
                end
                generators_index += 1;
            }
        end
    end

    class Integer < Fudge
        def initialize(delta = 128)
            super([0, 0x7FFF, 0xFFFF, 0x7FFFFFFF,
                   0x7FFFFFFFFFFFFFFF], delta)
        end
    end

    class Byte < Fudge
        def initialize(delta = 16)
            super([0x00, 0x01, 0x7F, 0xFF], delta, 0xFF)
        end
    end

    class Short < Fudge
        def initialize(delta = 128)
            super([0x0000, 0x0001, 0x7FFF, 0xFFFF], delta, 0xFFFF)
        end
    end

    class Long < Fudge
      def initialize(delta = 256)
        super([0x00000000, 0x0000001, 0x7FFFFFFF, 0xFFFFFFFF, 0x40000000, 0xC0000000], delta, 0xffffffff)
      end
    end

    class Char < Generator
      def initialize(c=:default)
        c = case c
        when :all
          (0..256).map(&:chr)
        when :alpha
          ('A'..'Z').to_a + ('a'..'z').to_a
        when Enumerable
          c
        else
          ["A", "0", "~", "`", "!", "@", "#", "$", "%", "^", "&",
           "*", "(", ")", "-", "=", "+", "[", "]", "|",
           ":", "'", "\"", ",", "<", ".", ">", "/",
           " ", "~", "_", "{", "}", "\x7f","\x00",
           "\x88","\x89","\x8f",
           "\x98","\x99","\x9f",
           "\xa8","\xa9","\xaf",
           "\xb8","\xb9","\xbf",
           "\xc8","\xc9","\xcf",
           "\xd8","\xd9","\xdf",
           "\xe8","\xe9","\xef",
           "\xf8","\xf9","\xff", ]
         else
          super(c)
      end
    end

    class Sequential < Generator
      def initialize *generators
        super() do |g|
          generators.each do |gen|
            gen.each do |val|
              g.yield val
            end
          end
        end
      end

      def next?
        begin
          self.peek
          true
        rescue StopIteration
          false
        end
      end

      def to_a; self; end
      def shift; next? ? self.next : nil; end
      def empty?; !self.next?; end
    end

    class String < Generator
        def initialize(lengths = nil, strings = nil, chars = nil)
            super() { |g|
                # Fuzz strings are each of CHARS repeated each of
                # LENGTHS times and each of strings
                lengths ||= [16, 32, 64, 100, 128, 192, 256, 384, 512, 768, 1024, 2048, 3072, 4096, 6000, 8192, 10000, 16000, 20000, 32000, 50000, 64000, 72000,  100000]
                strings ||= [
                    "%n%n%n%n%n%n%n%n%n%n", "%252n%252n%252n%252n%252n",
                    "%x%x%x%x", "%252x%252x%252x%252x",
                    "../../../../../../../../../../../../../etc/passwd",
                    "../../../../../../../../../../../../../etc/passwd%00",
                    "../../../../../../../../../../../../../boot.ini",
                    "../../../../../../../../../../../../../boot.ini%00",
                    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini",
                    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\boot.ini%00",
                    "<script>alert('XSS');</script>",
                    "A0`~!@#\$\%^&*()-_=+[]{}\\|;:',.<>/\""
                ]
                chars ||= Char.new()
                while chars.next?
                    c = chars.next

                    lengths.each { |l|
                        g.yield(c * l)
                    }
                end

                strings.each { |s|
                    g.yield(s)
                }
            }
        end
    end

    #
    # Modules for higher-level tokens (e-mail addresses, asn1, etc)
    #
    class EmailAddress < Generator
        def initialize()
        end
    end

end

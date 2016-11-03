module DFuzz
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
end

module DFuzz
  class Char < Generator
    def initialize(c=:default)
      c = case c
      when :all
        (0..256).map(&:chr)
      when :alpha
        ('A'..'Z').to_a + ('a'..'z').to_a
      when Enumerator
        c
      when ::String
        c.chars
      when :default
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
         "\xf8","\xf9","\xff"
       ]
      else
        c.to_enum
      end
      super() {|yldr|
        c.each do |char|
          yldr.yield char
        end
      }
    end
  end
end

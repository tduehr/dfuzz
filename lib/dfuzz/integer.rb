module DFuzz
  class Integer < Fudge
      def initialize(delta = 0x80)
          super([0, 0x7FFF, 0xFFFF, 0x7FFFFFFF,
                 0x7FFFFFFFFFFFFFFF], delta)
      end
  end

  class Byte < Integer
      def initialize(delta = 0x10)
          super([0x00, 0x01, 0x7F, 0xFF], delta, 0xFF)
      end
  end

  class Short < Integer
      def initialize(delta = 0x80)
          super([0x0000, 0x0001, 0x7FFF, 0xFFFF], delta, 0xFFFF)
      end
  end

  class Long < Integer
    def initialize(delta = 0x10000)
      super([0x00000000, 0x0000001, 0x7FFFFFFF, 0xFFFFFFFF, 0x40000000, 0xC0000000], delta, 0xffffffff)
    end
  end

  class LongLong < Integer
    def initialize(delta = 100000000)
      super([0x00000000, 0x0000001, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFF, 0x4000000000000000, 0xC000000000000000], delta, 0xffffffffffffffff)
    end
  end
end
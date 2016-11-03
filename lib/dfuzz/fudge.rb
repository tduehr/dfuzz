require 'dfuzz/generator'

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
end

module DFuzz
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
end

module DFuzz
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
end

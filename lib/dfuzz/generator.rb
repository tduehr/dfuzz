module DFuzz
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

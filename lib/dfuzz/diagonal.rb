module DFuzz
  class Diagonal < Generator
    attr_accessor :enums
    def initialize *enums
      @enums = enums

      super() do |yldr|
        while !@enums.empty?
          @enums.dup.each do |enum|
            begin
              yldr.yield enum.next
            rescue StopIteration
              @enums.delete enum
            end
          end
        end
      end
    end
  end
end

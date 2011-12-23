require 'helper'

class TestDfuzz < Test::Unit::TestCase
  def test_integers
    i = 0
    integers = DFuzz::Integer.new()
    while integers.next?
        integers.next
        i += 1
    end
    assert_equal(1290, i)
  end

  def test_bytes
    i = 0
    bytes = DFuzz::Byte.new()
    while bytes.next?
        bytes.next
        i += 1
    end
    assert_equal(136,i)
  end

  def test_shorts
    i = 0
    shorts = DFuzz::Short.new()
    while shorts.next?
        shorts.next
        i += 1
    end
    assert_equal(1032, i)
  end
  
  def test_longs
    i = 0
    longs = DFuzz::Long.new()
    while longs.next?
        longs.next
        i += 1
    end
    assert_equal(3084, i)
  end

  def test_chars
    i = 0
    characters = DFuzz::Char.new()
    while characters.next?
        characters.next
        i += 1
    end
    assert_equal(197, i)
  end

  def test_strings
    i = 0
    strings = DFuzz::String.new([1,2])
    while strings.next?
        strings.next
        i += 1
    end
    assert_equal(406, i)
  end
  
  def test_blocks
    require 'pp'
    b = DFuzz::Block.new(["FOO", "BAR"],
                        [DFuzz::String.new([1]), DFuzz::String.new([2])])
    i = 0
    b.run() { |a, b|
        i += 1
    }
    assert_equal(419, i)
  end
end

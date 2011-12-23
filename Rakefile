# encoding: utf-8

require 'rubygems'
require 'rake'

require 'jeweler'
Jeweler::Tasks.new do |gem|
  # gem is a Gem::Specification... see http://docs.rubygems.org/read/chapter/20 for more options
  gem.name = "dfuzz"
  gem.homepage = "http://github.chi.matasano.com/td/dfuzz"
  gem.license = "private"
  gem.summary = %Q{Fuzz generators}
  gem.description = %Q{Fuzzing payload generators for pentesting}
  gem.email = "td@matasano.com"
  gem.authors = ["tduehr", "Dino Dai Zovi"]
  gem.add_development_dependency "jeweler", "~> 1.6.4"
end
Jeweler::RubygemsDotOrgTasks.new

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
  test.libs << 'lib' << 'test'
  test.pattern = 'test/**/test_*.rb'
  test.verbose = true
end

begin
  require 'rcov/rcovtask'
  Rcov::RcovTask.new do |test|
    test.libs << 'test'
    test.pattern = 'test/**/test_*.rb'
    test.verbose = true
    test.rcov_opts << '--exclude "gems/*"'
  end
rescue LoadError
end

task :default => :test

begin
  require 'yard'
  YARD::Rake::YardocTask.new
rescue LoadError
  warn 'yard not found'
end
# encoding: utf-8

require 'rake'

require 'jeweler'
Jeweler::Tasks.new do |gem|
  # gem is a Gem::Specification... see http://docs.rubygems.org/read/chapter/20 for more options
  gem.name = "dfuzz"
  gem.homepage = "http://github.com/tduehr/dfuzz"
  gem.summary = %Q{Fuzz generators}
  gem.description = %Q{Fuzzing payload generators for pentesting}
  gem.email = "timur.duehr@nccgroup.trust"
  gem.authors = ["tduehr", "Dino Dai Zovi"]
  gem.add_development_dependency "jeweler", "~> 2.1.2"
  gem.add_development_dependency "yard", "~> 0.9.5"
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

require 'yard'
YARD::Rake::YardocTask.new

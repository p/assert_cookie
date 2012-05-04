require 'rake'
require 'rake/testtask'
begin
  require 'rdoc/task'
  have_rdoc = true
rescue LoadError => e
  begin
    require 'rake/rdoctask'
    have_rdoc = true
  rescue LoadError => ee
    STDERR.puts "Could not require rdoc/task or rake/rdoctask: #{e.class}: #{e.message}; #{ee.class}: #{ee.message}"
    have_rdoc = false
  end
end

desc 'Default: run unit tests.'
task :default => :test

desc 'Test the assert_cookie plugin.'
Rake::TestTask.new(:test) do |t|
  t.libs << 'lib'
  t.pattern = 'test/**/*.rb'
  t.verbose = true
end

if have_rdoc
  desc 'Generate documentation for the assert_cookie plugin.'
  Rake::RDocTask.new(:rdoc) do |rdoc|
    rdoc.rdoc_dir = 'rdoc'
    rdoc.title    = 'assert_cookie'
    rdoc.rdoc_files.include('README')
    rdoc.rdoc_files.include('lib/**/*.rb')
  end
end

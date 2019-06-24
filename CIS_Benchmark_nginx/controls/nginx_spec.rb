nginx_params = yaml(content: inspec.profile.file('params.yml')).params

forbidden_modules = nginx_params['forbidden-modules']

# you add controls here
control 'verify-modules' do                        # A unique ID for this control
  impact 1.0                                # The criticality, if this control fails.
  title 'Verify that certain modules are not installed' # A human-readable title
  desc 'These modules should not be installed, see CIS NGINX Benchmark Chapter 2 for more information'
  describe nginx do
    forbidden_modules.each do |forbidden_module|           # The actual test
    	its ('modules') { should_not include forbidden_module }
  	end
  end
end

control 'verify-ownership-01' do
	impact 1.0
	title 'Verify that owner and group of the /etc/nginx directory and its files is root'
	desc 'Setting ownership to only those users in the root group and the root user will reduce the likelihood of unauthorized modifications to the nginx configuration files'
	
	nginx_files = command('find /etc/nginx -print').stdout.split
	nginx_files.each do |file|
		describe file(file) do
			its('owner') {should eq 'root'}
			its('group') {should eq 'root'}
    	end
  	end
end



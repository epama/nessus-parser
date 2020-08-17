use Parse::CSV;

my @files = (
	####################### ADD MORE CSV NESSUS FILES
);

my $master = {};
my @grouping = (
				["tomcat"],
				["apache"],
				["php"],
				["esxi","vmware"],
				["db2"],
				["mariadb"],
				["mysql"],
				["ntp"],
				["iis"],
				["ssl"],
				["openssh"]
);

foreach my $file (@files){
	load_file($file,$master);
}

output($master);

sub load_file {
	my ($file,$master) = @_;

	my $simple = Parse::CSV->new(
	    file => $file
	);

	my $x = 0;

	while ( my $line = $simple->fetch ) {
	    
	    if($x <= 0){ ####### SKIP HEADER
	    	$x++;
	    	next;
	    }

	    by_vuln($line,$master);
	}
}

sub by_vuln {
	my ($array_ref,$master) = @_;

	my $hash = $master;

	my $ip = ${$array_ref}[4];
    my $severity = ${$array_ref}[3];
    my $plugin_id = ${$array_ref}[0];
	my $port = ${$array_ref}[6];

	my $cve = ${$array_ref}[1];

	if($cve =~ /cve\-\d+\-\d+/i){
		$hash->{$severity}->{$plugin_id}->{"cve"}->{$cve} = 1;
	}

	my (@cves_desc) = $hash->{$severity}->{$plugin_id}->{"description"} =~ /(cve\-\d+\-\d+)/ig;

	foreach my $cves_desc (@cves_desc){
		$hash->{$severity}->{$plugin_id}->{"cve"}->{$cves_desc} = 1;
	}

    if(!defined($hash->{$severity}->{$plugin_id}->{"name"})){
    	my $name = ${$array_ref}[7];
    	$hash->{$severity}->{$plugin_id}->{"name"} = $name;
	}
	
	if(!defined($hash->{$severity}->{$plugin_id}->{"description"})){
    	my $description = ${$array_ref}[9];
    	$hash->{$severity}->{$plugin_id}->{"description"} = $description;
	}

	if(!defined($hash->{$severity}->{$plugin_id}->{"output"})){
   		my $output = ${$array_ref}[12];
    	$hash->{$severity}->{$plugin_id}->{"output"} = $output;
	}


	if(!defined($hash->{$severity}->{$plugin_id}->{"solution"})){
   		my $solution = ${$array_ref}[10];
    	$hash->{$severity}->{$plugin_id}->{"solution"} = $solution;
	}

	if(!defined($hash->{$severity}->{$plugin_id}->{"ip"}->{$ip})){
		$hash->{$severity}->{$plugin_id}->{"ip"}->{$ip} = ();
	}

	push @{$hash->{$severity}->{$plugin_id}->{"ip"}->{$ip}}, $port;
}

sub appendix_b_output {
	my ($hash,$severity) = @_;

	print "Severity: ".$severity."\n";

	foreach my $plugin_id (keys %{$hash->{$severity}}){
		my $name = $hash->{$severity}->{$plugin_id}->{"name"};

		print $name."\n\n";

		print "IPs:\n\n";
		foreach my $ip (keys %{$hash->{$severity}->{$plugin_id}->{"ip"}}){
			print $ip."\n";
		}

		print "----------------------------------\n\n";
	}

	print "============================================\n\n";
}

sub open_port_output {
	my ($hash) = @_;

	foreach my $ip (keys %{$hash->{"None"}->{"11219"}->{"ip"}}){
		print $ip."\n";

		foreach my $port (@{$hash->{"None"}->{"11219"}->{"ip"}->{$ip}}){
			print $port."\n";
		}
	}

}

sub narrative_per_vulnerability_output {
	my ($hash,$severity) = @_;

	print "Severity: ".$severity."\n";

	foreach my $plugin_id (keys %{$hash->{$severity}}){
		print $plugin_id."\n";

		my $name = $hash->{$severity}->{$plugin_id}->{"name"};
		print $name."\n\n";

		print "CVEs:\n\n";

		foreach my $cve (keys %{$hash->{$severity}->{$plugin_id}->{"cve"}}){
			print $cve."\n";
		}

		print "\n";

		print "IPs:\n\n";

		foreach my $ip (keys %{$hash->{$severity}->{$plugin_id}->{"ip"}}){
			print $ip."\n";
		}

		my $description = $hash->{$severity}->{$plugin_id}->{"description"};

		print "\nDescription:\n";
		print $description."\n\n";


		my $output = $hash->{$severity}->{$plugin_id}->{"output"};

		print "\nOutput:\n";
		print $output."\n\n";

		my $solution = $hash->{$severity}->{$plugin_id}->{"solution"};

		print "\nRemediation:\n";
		print $solution."\n\n";

		print "----------------------------------\n\n";
	}

	print "============================================\n\n";
}

sub vuln_list {
	my ($hash) = @_;

	#print "Severity: ".$severity."\n";

	my $grouped;
	my @ungrouped = ();


	my @severities = (
		"Critical",
		"High",
		"Medium"
	);

	foreach my $severity(@severities){
		foreach my $plugin_id (keys %{$hash->{$severity}}){
			my $name = $hash->{$severity}->{$plugin_id}->{"name"};

			my $hit = 0;

			
			foreach my $group (@grouping){
				my $group_hit = 0;
				my $index = "";
				foreach my $g (@$group){
					$index = $index.$g;
					if ($name =~ /$g/i){
						$hit = 1;
						$group_hit = 1;
					}
				}

				if($group_hit == 1){
					if(!defined($grouped->{$index}->{"name"})){
						$grouped->{$index}->{"name"} = ();
					}
					push @{$grouped->{$index}->{"name"}}, $name;


					foreach my $ip (keys %{$hash->{$severity}->{$plugin_id}->{"ip"}}){
						if(!defined($grouped->{$index}->{"ip"}->{$ip})){
							$grouped->{$index}->{"ip"}->{$ip} = 1;
						}
					}

					foreach my $cve (keys %{$hash->{$severity}->{$plugin_id}->{"cve"}}){
						if(!defined($grouped->{$index}->{"cve"}->{$cve})){
							$grouped->{$index}->{"cve"}->{$cve} = 1;
						}
					}
					last;
				}
			}

			if($hit == 0){
				push @ungrouped, $name;
			}
		}
	}

	foreach my $print_group (keys %{$grouped}){
		print $print_group."\n";

		@sorted_grouped_name = sort @{$grouped->{$print_group}->{"name"}};

		foreach my $group_name (@sorted_grouped_name){
			print $group_name."\n";
		}

		print "\n";

		my @grouped_ip = keys %{$grouped->{$print_group}->{"ip"}};

		my @sorted_grouped_ip = sort @grouped_ip;

		print "IPs:\n\n";

		foreach my $group_ip (@sorted_grouped_ip){
			print $group_ip."\n";
		}

		print "\n";

		my @grouped_cve = keys %{$grouped->{$print_group}->{"cve"}};

		my @sorted_grouped_cve = sort @grouped_cve;

		if(@sorted_grouped_cve > 1){
			print "CVEs:\n\n";
		}

		foreach my $group_cve (@sorted_grouped_cve){
			print $group_cve."\n";
		}
		
		print "\n";

		print "-------------------------------------------\n";
	}

	foreach my $print_nongroup(@ungrouped){
		print $print_nongroup."\n";
	}
	print "-------------------------------------------\n";
	

	print "============================================\n\n";

}

sub output {
	my ($master) = @_;

	print "Narrative Per Vulnerability Output\n\n";

	narrative_per_vulnerability_output($master,"Critical");
	narrative_per_vulnerability_output($master,"High");
	narrative_per_vulnerability_output($master,"Medium");
	#narrative_per_vulnerability_output($master,"Low");
	#narrative_per_vulnerability_output($master,"None");


	print "<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>\n\n\n";

	print "Appendix B\n\n";

	appendix_b_output($master,"Critical");
	appendix_b_output($master,"High");
	appendix_b_output($master,"Medium");
	#appendix_b_output($master,"Low");
	#appendix_b_output($master,"None");

	print "<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>\n\n\n";

	print "Summary Vuln List \n\n";
	vuln_list($master);

	
	print "<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>\n\n\n";

	print "Open Port \n\n";

	open_port_output($master);
}






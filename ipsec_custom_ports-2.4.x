diff -ru a/src/etc/inc/filter.inc b/src/etc/inc/filter.inc
--- a/src/etc/inc/filter.inc	2020-09-05 12:13:09.633926000 +0200
+++ b/src/etc/inc/filter.inc	2020-09-05 12:13:21.047678000 +0200
@@ -4341,10 +4341,18 @@
 			/* If NAT-T is enabled, add additional rules */
 			if ($ph1ent['nat_traversal'] != "off") {
 				if ($rgip != " any ") {
-					$ipfrules .= "pass out {$log['pass']} $route_to proto udp from (self) to {$rgip} port = 4500 tracker {$increment_tracker($tracker)} keep state label \"IPsec: {$shorttunneldescr} - outbound nat-t\"\n";
+					$ikeport = 4500;
+					if ( isset($ph1ent['ikeport']) ) {
+						$ikeport = $ph1ent['ikeport'];
+					}
+					$ipfrules .= "pass out {$log['pass']} $route_to proto udp from (self) to {$rgip} port = $ikeport tracker {$increment_tracker($tracker)} keep state label \"IPsec: {$shorttunneldescr} - outbound nat-t\"\n";
+				}
+				$port_nat_t = 4500;
+				if ( isset($config['ipsec']['port_nat_t']) ) {
+					$port_nat_t = $config['ipsec']['port_nat_t'];
 				}
 				$ipfrules .= <<<EOD
-pass in {$log['pass']} on \${$FilterIflist[$parentinterface]['descr']} $reply_to proto udp from {$rgip} to (self) port = 4500 tracker {$increment_tracker($tracker)} keep state label "IPsec: {$shorttunneldescr} - inbound nat-t"
+pass in {$log['pass']} on \${$FilterIflist[$parentinterface]['descr']} $reply_to proto udp from {$rgip} to (self) port = $port_nat_t tracker {$increment_tracker($tracker)} keep state label "IPsec: {$shorttunneldescr} - inbound nat-t"
 
 EOD;
 			}
diff -ru a/src/etc/inc/vpn.inc b/src/etc/inc/vpn.inc
--- a/src/etc/inc/vpn.inc	2020-09-05 12:13:09.634039000 +0200
+++ b/src/etc/inc/vpn.inc	2020-09-05 16:41:47.341480000 +0200
@@ -404,6 +404,11 @@
 		$makebeforebreak = 'make_before_break = yes';
 	}
 
+	$port_nat_t = '';
+	if (isset($config['ipsec']['port_nat_t'])) {
+		$port_nat_t = 'port_nat_t = ' . $config['ipsec']['port_nat_t'];
+	}
+
 	if (isset($config['ipsec']['enableinterfacesuse'])) {
 		if (!empty($ifacesuse)) {
 			$ifacesuse = 'interfaces_use = ' . implode(',', array_unique($ifacesuse));
@@ -445,6 +450,7 @@
 	cisco_unity = {$unity_enabled}
 	{$ifacesuse}
 	{$makebeforebreak}
+        {$port_nat_t}
 
 	syslog {
 		identifier = charon
@@ -1185,6 +1191,18 @@
 				}
 			}
 
+			$leftikeport = '';
+			$rightikeport = '';
+			if (isset($ph1ent['ikeport'])) {
+				if (isset($config['ipsec']['port_nat_t'])) {
+					$leftikeport = 'leftikeport = ' . $config['ipsec']['port_nat_t'];
+				}
+				else {
+					$leftikeport = 'leftikeport = 4500';
+				}
+				$rightikeport = 'rightikeport = ' . $ph1ent['ikeport'];
+			}
+
 			$ipseclifetime = 0;
 			$rightsubnet_spec = array();
 			$leftsubnet_spec = array();
@@ -1385,6 +1403,8 @@
 	auto = {$passive}
 	left = {$left_spec}
 	right = {$right_spec}
+	${leftikeport}
+	${rightikeport}
 	{$leftid}
 
 EOD;
diff -ru a/src/usr/local/www/vpn_ipsec_phase1.php b/src/usr/local/www/vpn_ipsec_phase1.php
--- a/src/usr/local/www/vpn_ipsec_phase1.php	2020-09-05 12:11:49.743850000 +0200
+++ b/src/usr/local/www/vpn_ipsec_phase1.php	2020-09-05 12:12:38.333539000 +0200
@@ -80,6 +80,7 @@
 		$pconfig['mobile'] = 'true';
 	} else {
 		$pconfig['remotegw'] = $a_phase1[$p1index]['remote-gateway'];
+		$pconfig['ikeport'] = $a_phase1[$p1index]['ikeport'];
 	}
 
 	if (empty($a_phase1[$p1index]['iketype'])) {
@@ -471,6 +472,11 @@
 			$ph1ent['mobile'] = true;
 		} else {
 			$ph1ent['remote-gateway'] = $pconfig['remotegw'];
+			if ( !empty($pconfig['ikeport']) && $pconfig['ikeport'] != '500' ) {
+				$ph1ent['ikeport'] = $pconfig['ikeport'];
+			} else {
+				unset($ph1ent['ikeport']);
+			}
 		}
 
 		$ph1ent['protocol'] = $pconfig['protocol'];
@@ -719,12 +725,22 @@
 ))->setHelp('Select the interface for the local endpoint of this phase1 entry.');
 
 if (!$pconfig['mobile']) {
-	$section->addInput(new Form_Input(
+	$group = new Form_Group('*Remote Gateway');
+	$group->add(new Form_Input(
 		'remotegw',
 		'*Remote Gateway',
 		'text',
 		$pconfig['remotegw']
 	))->setHelp('Enter the public IP address or host name of the remote gateway.');
+
+	$group->add(new Form_Input(
+        	'ikeport',
+	        'Remote port',
+	        'number',
+        	$pconfig['ikeport'],
+	        ['min' => 1, 'max' => 65535]
+	))->setHelp('Enter a custom port number for IPsec (leave empty for 500/4500)');
+	$section->add($group);
 }
 
 $section->addInput(new Form_Input(
diff -ru a/src/usr/local/www/vpn_ipsec_settings.php b/src/usr/local/www/vpn_ipsec_settings.php
--- a/src/usr/local/www/vpn_ipsec_settings.php	2020-09-05 12:11:49.743894000 +0200
+++ b/src/usr/local/www/vpn_ipsec_settings.php	2020-09-05 12:12:51.229419000 +0200
@@ -170,6 +170,12 @@
 			}
 		}
 
+                if (!empty($_POST['port_nat_t']) && $_POST['port_nat_t'] != '500' ) {
+                        $config['ipsec']['port_nat_t'] = $_POST['port_nat_t'];
+                } else {
+                        unset($config['ipsec']['port_nat_t']);
+                }
+
 		write_config(gettext("Saved IPsec advanced settings."));
 
 		$changes_applied = true;
@@ -360,6 +366,14 @@
 ))->setHelp('Allow crypto(9) jobs to be dispatched multi-threaded to increase performance. ' .
 		'Jobs are handled in the order they are received so that packets will be reinjected in the correct order.');
 
+$section->addInput(new Form_Input(
+        'port_nat_t',
+        'Listen port',
+        'number',
+        $config['ipsec']['port_nat_t'],
+        ['min' => 1, 'max' => 65535]
+))->setHelp('Enter a custom port number for IPsec (leave empty for 500)');
+
 $form->add($section);
 
 print $form;

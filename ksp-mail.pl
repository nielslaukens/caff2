#!/usr/bin/env perl

# script to post-process a keyring after a key signing party
#
# Inputs:
#  * A list of (partially signed) keys on stdin
#  * A list of long keyids (16 characters) as argument
#
# Output:
#  * A list of mail messages in the current directory, suitable for piping to
#    `sendmail -t`
#
# The given keys are split into pieces, and reassembled. The reassembled keys
# only contain the master key, a single UID/UAT, the self-signature on that
# UID/UAT, and the signature made by one of the given keyid(s).
#
# Each signed UID/UAT will be mailed to the corresponding email address,
# UATs and UIDs without email address are sent to all email-addresses of the
# same key (even if these were not signed). (Contrary to `caff`, these will be
# separate messages)
#
# Each mail will be encrypted with both the key it is about, and the keyid
# that signed it.
#
# You can edit the template of the mail below to fit your needs

my $message_template = <<'EOM';
Hi,

please find attached the user id
    {$uid}
of your key {$key} signed by me ({$mykey}).

If you have multiple user ids, I sent the signature for each user id
separately to that user id's associated email address. For user id's or
user attributes without an associated email address, I sent the
signatures to each email address found on the key. You can import the
signatures by running each through `gpg --import`.

Note that I did not upload your key to any keyservers. If you want this
new signature to be available to others, please upload it yourself.
With GnuPG this can be done using
	gpg --keyserver pool.sks-keyservers.net \
		--send-key {$key}

If you have any questions, don't hesitate to ask.

Regards
EOM

my $gpg_command = "gpg2";



use strict;
use warnings;

use Text::Template;
use MIME::Entity;
use MIME::QuotedPrint ();
use File::Temp qw/tempdir/;
use IPC::Open3;
use Crypt::OpenPGP::Armour;



if( @ARGV == 0 ) {
	print STDERR "Usage: $0 keyid ... < keyring\n";
	exit 64;
}
my @mykeyid = @ARGV; @ARGV = ();

if( -t *STDIN ) {
	print STDERR "Expecting GPG keyring on stdin...\n";
}


my @key;
# Generate a structure like;
# [
#   {
#     master => "<binary master key packet>",
#     keyid => "<keyid in hex text>",
#     uid => [
#       {
#         uid => "<binary uid packet>"
#         uid_text => "First Last <email@domain.com>", # only for UIDs
#         uat => 1, # only for UATs
#         selfsig => "<binary sig packet>"
#         sig => [
#           {
#             packet => "<binary sig packet>"
#             keyid => "<signer keyid in hex text>"
#           },
#           ...
#       },
#       ...
#     ],
#   },
#   ...
# ]
sub process_packet {
	my ($packetbin, $packet) = @_;
	my @line = split /\n/, $packet;

	if( $line[1] =~ m/^:public key packet:/ ) {
		# master key
		$packet =~ m/^\tkeyid: ([0-9a-fA-F]+)/m
			or die("Couldn't find '^\\tkeyid: ' in public key packet:\n$packet");
		my $keyid = $1;

		push @key, {
			master => $packetbin,
			keyid => $keyid,
			uid => [],
		};

	} elsif( $line[1] =~ m/^:user ID packet: "(.*)"$/ ) {
		my $uid = $1;
		$uid =~ s/\\x([A-Fa-f\d]{2})/chr hex $1/eg;
		push @{$key[-1]->{uid}}, {
			uid => $packetbin,
			uid_text => $uid,
			selfsig => undef,
			sig => [],
		};

	} elsif( $line[1] =~ m/^:attribute packet:/ ) {
		push @{$key[-1]->{uid}}, {
			uid => $packetbin,
			uat => 1,
			selfsig => undef,
			sig => [],
		};

	} elsif( $line[1] =~ m/^:signature packet: algo [0-9a-fA-F]{1,3}, keyid ([0-9a-fA-F]+)/ ) {
		my $sig_by = $1;

		$packet =~ m/\bsigclass 0x([0-9a-fA-F]{2})/
			or die("could not find '\\bsigclass 0x' in signature packet\n:$packet");
		my $sigclass = hex($1);

		if( $packet !~ m/\bhashed subpkt 4 len 1 \(not exportable\)$/m ) {
			# only loop over exportable signatures.

			if( $sigclass >= 0x10 && $sigclass <= 0x13 ) {
				# certification signature
				if( $sig_by eq $key[-1]->{keyid} ) {
					# self signature
					print STDERR "WARNING: multiple selfsigs" if defined $key[-1]->{uid}[-1]->{selfsig};
					$key[-1]->{uid}[-1]->{selfsig} = $packetbin;

				} elsif( grep { $_ eq $sig_by } @mykeyid ) {
					# signature by @mykey
					push @{ $key[-1]->{uid}[-1]->{sig} }, {
							packet => $packetbin,
							keyid => $sig_by,
						};
				}
			} elsif( $sigclass == 0x30 ) {
				# Revokation
				if( $sig_by eq $key[-1]->{keyid} ) {
					# self signature
					$key[-1]->{uid}[-1]->{revoked} = 1;
				}
			}
		}

	} else {
		#ignore
	}
}


my $gnupghome = tempdir(CLEANUP => 1);
print STDERR "Processing input keys...\n";
{	# Parse keys from STDIN
	my $keys = do { local $/; <> };

	open(my $fh, ">", "$gnupghome/input.gpg")
		or die("Couldn't save input");
	print $fh $keys;
	close $fh;

	my $ret = system($gpg_command, "--homedir", $gnupghome, "-q",
	                 "--import", "$gnupghome/input.gpg");
	die("Could not start gpg") if $ret != 0;
	print STDERR "    imported into gpg\n";

	open($fh, "-|", $gpg_command, "--list-packets", "$gnupghome/input.gpg")
		or die("Couldn't list packets of input");

	my $state=0;
	my $packet = undef;
	my $packetbin = undef;
	while(my $line = <$fh>) {
		if( $line =~ m/^# off=(\d+) ctb=([0-9a-fA-F]+) tag=(\d+) hlen=(\d+) plen=(\d+)/ ) {
			my ($offset, $hlen, $plen) = ($1, $4, $5);
			process_packet $packetbin, $packet if defined $packet;
			$packetbin = substr($keys, $offset, $hlen+$plen);
			$packet = $line;
			die("Unexpected #-line in state $state") unless $state == 0;
			$state = 1;
		} elsif( $line =~ m/^:([^:]+):(.*)/ ) {
			$packet .= $line;
			die("Unexpected :-line in state $state") unless $state == 1;
			$state = 0;
		} elsif( $line =~ m/^\t(.*)/ ) {
			$packet .= $line;
			die("Unexpected tab-line in state $state") unless $state == 0;
			$state = 0;

		} else {
			print STDERR "Unknown line in list-packets output:\n$line";
		}
	}
	process_packet $packetbin, $packet if defined $packet;
	close $fh;

	print STDERR "    " . scalar(@key) . " keys done\n";
}

print STDERR "Filtering non-self-signed and revoked UID/UATs and keys...\n";
{	# Filter out non-self-signed or revoked UIDs
	for(my $ikey = 0; $ikey < scalar(@key); $ikey++) {
		for(my $iuid = 0; $iuid < scalar(@{$key[$ikey]->{uid}}); $iuid++) {
			if( !defined($key[$ikey]->{uid}[$iuid]->{selfsig})
			 || $key[$ikey]->{uid}[$iuid]->{revoked}
			  ) {
				splice(@{ $key[$ikey]->{uid} }, $iuid, 1);
				$iuid--;
			}
		}
		if( @{ $key[$ikey]->{uid} } == 0 ) {
			splice(@key, $ikey, 1);
			$ikey--;
		}
	}
	print STDERR "    done: " . scalar(@key) . " keys remaining\n";
}

print STDERR "Mapping UIDs to email addresses to use...\n";
{	# Figure out to what mail addresses things should be mailed
	for(my $ikey = 0; $ikey < scalar(@key); $ikey++) {
		# Make a list of all email addresses
		my @email;
		my @uid_without_email;
		for(my $iuid = 0; $iuid < scalar(@{$key[$ikey]->{uid}}); $iuid++) {
			my $uid_text = $key[$ikey]->{uid}[$iuid]->{uid_text};
			if( defined $uid_text && $uid_text =~ m/<([^<]+)>$/ ) {
				push @email, $1;
				$key[$ikey]->{uid}[$iuid]->{email} = [$1];
			} else {
				push @uid_without_email, $iuid;
			}
		}

		# Send non-email UID/UATs to all email addresses
		for my $iuid (@uid_without_email) {
			$key[$ikey]->{uid}[$iuid]->{email} = [@email];
		}
	}
	print STDERR "    done\n";
}

print STDERR "Filtering non-signed UID/UATs and keys...\n";
{	# Filter out non-signed UIDs
	for(my $ikey = 0; $ikey < scalar(@key); $ikey++) {
		for(my $iuid = 0; $iuid < scalar(@{$key[$ikey]->{uid}}); $iuid++) {
			if( @{ $key[$ikey]->{uid}[$iuid]->{sig} } == 0 ) {
				# No sigs by @mykeyid
				splice(@{ $key[$ikey]->{uid} }, $iuid, 1);
				$iuid--;
			}
		}
		if( @{ $key[$ikey]->{uid} } == 0 ) {
			splice(@key, $ikey, 1);
			$ikey--;
		}
	}
	print STDERR "    done: " . scalar(@key) . " keys remaining\n";
}

print STDERR "Generating emails...\n\n";
{	# Generate emails for each (remaining) key/uid
	# see RFC2015 for MIME details
	my $count = 0;
	my $template = Text::Template->new(TYPE => 'STRING', SOURCE => $message_template)
		or die "Error creating template: $Text::Template::ERROR";

	for(my $ikey = 0; $ikey < scalar(@key); $ikey++) {
		for(my $iuid = 0; $iuid < scalar(@{$key[$ikey]->{uid}}); $iuid++) {
			for(my $isig = 0; $isig < scalar(@{$key[$ikey]->{uid}[$iuid]->{sig}}); $isig++) {
				my $keyid = uc($key[$ikey]->{keyid});
				my $mykeyid = uc($key[$ikey]->{uid}[$iuid]->{sig}[$isig]->{keyid});
				my $uid = defined($key[$ikey]->{uid}[$iuid]->{uat}) ?
						"[user attribute]" :
						$key[$ikey]->{uid}[$iuid]->{uid_text};

				# overwrite previous line
				my $statusline = sprintf "    Key %d/%d (0x%s), UID %d/%d (%s), sig %d/%d (0x%s)",
					$ikey, scalar(@key), $keyid,
					$iuid, scalar(@{$key[$ikey]->{uid}}), $uid,
					$isig, scalar(@{$key[$ikey]->{uid}[$iuid]->{sig}}),
						$mykeyid;
				# Crop line to terminal width
				$statusline = substr $statusline, 0, `tput cols`;
				printf STDERR "\x1b[A\x1b[2K$statusline\n",

				my $mail_body = $template->fill_in(HASH => {
						uid => $uid,
						key => $keyid,
						mykey => $mykeyid,
					})
					or die "Error filling template in: $Text::Template::ERROR";

				my $message_entity = MIME::Entity->build(
					Type        => "text/plain",
					Disposition => 'inline',
					Charset     => "utf-8",
					Encoding    => "quoted-printable",
					# Data is automatically quoted-printable-encoded
					Data        => $mail_body,
				);

				my $key = '';
				$key .= $key[$ikey]->{master};
				$key .= $key[$ikey]->{uid}[$iuid]->{uid};
				$key .= $key[$ikey]->{uid}[$iuid]->{selfsig};
				$key .= $key[$ikey]->{uid}[$iuid]->{sig}[$isig]->{packet};
				my $armored_key = Crypt::OpenPGP::Armour->armour(
						Data => $key,
						Object => "PUBLIC KEY BLOCK",
						Headers => {},
					);

				$message_entity->attach(
					Type        => "application/pgp-keys",
					Disposition => 'attachment',
					Encoding    => "7bit",
					Data        => $armored_key,
					Filename    => sprintf("0x%s.%d.signed-by-0x%s.asc",
					                       $keyid, $iuid, $mykeyid),
				);

				# Try to encrypt
				$message_entity = try_encrypt($message_entity, $keyid, $mykeyid);

				$message_entity->head->add( "Subject",
					"Your signed PGP key 0x$keyid" );
				for my $rcpt (@{ $key[$ikey]->{uid}[$iuid]->{email} }) {
					$message_entity->head->add( "To", $rcpt );
				}

				open my $fh, ">", sprintf("%s.%d.signed-by-%s.msg",
				                          $keyid, $iuid, $mykeyid);
				print $fh $message_entity->stringify();
				close $fh;
				$count++;
			}
		}
	}
	print STDERR "    $count mails done\n";
}

sub try_encrypt {
	# see RFC2015
	my ($message, @keyid) = @_;

	my($chld_out, $chld_in, $chld_err);
	my @cmd = ($gpg_command, '-q',
		'--always-trust', '--armor',
		map( { ('--recipient', $_) } @keyid),
		'--encrypt');
	my $pid = open3($chld_in, $chld_out, $chld_err, @cmd);

	print $chld_in $message->stringify();
	close $chld_in;

	my $encmessage = do { local $/; <$chld_out> };

	waitpid($pid, 0) or die("Could not wait for child process");
	if( $? ) {
		print STDERR "Could not encrypt for keys ", join(", ", @keyid), ":\n\n" .
			$encmessage . "\n" .
			do { local $/; <$chld_err> };
		return $message;
	}

	my $message_entity =
		MIME::Entity->build( Type =>
			'multipart/encrypted; protocol="application/pgp-encrypted"' );

	$message_entity->attach(
		Type        => "application/pgp-encrypted",
		Disposition => 'attachment',
		Encoding    => "7bit",
		Data        => "Version: 1\n"
	);

	$message_entity->attach(
		Type        => "application/octet-stream",
		Filename    => 'msg.asc',
		Disposition => 'inline',
		Encoding    => "7bit",
		Data        => $encmessage
	);

	return $message_entity;
}

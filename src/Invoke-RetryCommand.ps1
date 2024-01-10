<#
.SYNOPSIS
    Executes a command and retries it a maximum of time with a exponential delay
    Default is to retry 3 times with a delay of 100ms
.EXAMPLE
    PS C:\ Invoke-RetryCommand -ScriptBlock { Write-Output test } -Retries 3 -Delay 100
#>

function Invoke-RetryCommand {
    [CmdletBinding()]
    Param (
        [Parameter(Position=0, Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        [Parameter(Position=1, Mandatory=$false)]
        [int]$Retries = 3,
        [Parameter(Position=2, Mandatory=$false)]
        [int]$Delay = 100
    )
    Begin {
        $cnt = 0
    }
    Process {
        do {
            $cnt++
            try {
                $res = $ScriptBlock.Invoke()
                return $res
            }
            catch {
                Write-Error $_.Exception.InnerException.Message -ErrorAction Continue
                Start-Sleep -Milliseconds ($Delay * [Math]::Pow(2, $cnt - 1))
            }
        } while ($cnt -le $Retries)
        throw 'Execution failed.'
    }
}
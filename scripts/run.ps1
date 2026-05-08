# run.ps1
# Run as: .\run.ps1 [MachineID]
$PRIVATE_KEY = "private_1"
$PUBLIC_KEY = "public_1"

$arg0 = if ($args.Count -ge 1) { $args[0] } else { $null }
$arg1 = if ($args.Count -ge 2) { $args[1] } else { $null }
$arg2 = if ($args.Count -ge 3) { $args[2] } else { $null }

$env:MACHINE_ID = $arg0 ?? "0"
$env:PASETO_V4_PRIVATE_KEY = $arg1 ?? $PRIVATE_KEY
$env:PASETO_V4_PUBLIC_KEY = $arg2 ?? $PUBLIC_KEY

Write-Host "Server starting with MACHINE_ID=$($env:MACHINE_ID)" -ForegroundColor Green
go run ./cmd/server
# run_server.ps1
# Run as: .\run_server.ps1 [MachineID]
$PRIVATE_KEY = "k2XK5ZvU06iopt7xTGobruc9VM9ODJsjuWNij2v5w4Jn4xVsGiD7JXknnWe2BnVhHn190MKnnsXU/J8oNvppzw=="
$PUBLIC_KEY = "Z+MVbBog+yV5J51ntgZ1YR59fdDCp57F1PyfKDb6ac8="

# 1. Handle MACHINE_ID (Argument 0)
if ($args.Count -ge 1 -and $args[0]) {
    $env:MACHINE_ID = $args[0]
} else {
    $env:MACHINE_ID = "0"
}

# 2. Handle PRIVATE_KEY (Argument 1)
if ($args.Count -ge 2 -and $args[1]) {
    $env:PASETO_V4_PRIVATE_KEY = $args[1]
} else {
    $env:PASETO_V4_PRIVATE_KEY = $PRIVATE_KEY
}

# 3. Handle PUBLIC_KEY (Argument 2)
if ($args.Count -ge 3 -and $args[2]) {
    $env:PASETO_V4_PUBLIC_KEY = $args[2]
} else {
    $env:PASETO_V4_PUBLIC_KEY = $PUBLIC_KEY
}

Write-Host "Server starting with MACHINE_ID=$($env:MACHINE_ID)" -ForegroundColor Green
go run ./cmd/server

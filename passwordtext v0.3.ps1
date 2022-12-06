
<#
# generate the private key
$password = "password"
$privkey_hash = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
$privkey = $privkey_hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($password))
$privkey_string = [System.BitConverter]::ToString($privkey)
$privkey_string = $privkey_string.replace("-","")

[console]::Write("AAA`n$privkey_string`n")
#>

# encrypt function
function encrypt ($text, $password, $saltpassword){
    
    $privkey_hash = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')             # initialise 256 bit hashing algorithm
    $privkey = $privkey_hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($password))     # convert 256 bit hash into private key

    $salt_hash = [System.Security.Cryptography.HashAlgorithm]::Create('md5')                   # initialise 128 bit hashing algorithm
    $salt = $salt_hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($saltpassword))       # convert 128 bit hash into salt for initialisation vector
                                                                          
    $cipher = New-Object System.Security.Cryptography.AesCryptoServiceProvider       # create new cipher object
    $cipher.key = $privkey                                                           # set the private key
    $cipher.iv = $salt                                                               # set the salt hash
    $cipher_mode = $cipher.CreateEncryptor()                                         # create encryptor
    
    #encrypt with aes
    $plaintext_bytes = [System.Text.Encoding]::UTF8.GetBytes($text)                            # converts UTF-8 plaintext string into byte array
    $block_size = $plaintext_bytes.Length                                                      # calculates length of byte array
    $ciphertext_bytes = $cipher_mode.TransformFinalBlock($plaintext_bytes, 0, $block_size)     # transformation function for encryption
    $ciphertext_with_salt = $cipher.iv + $ciphertext_bytes
    $cipher.Dispose()                                                                          # frees up resources

    $ciphertext = [System.Convert]::ToBase64String($ciphertext_with_salt)                      # converts ciphertext byte array into base64 string
    return $ciphertext

}

# decrypt function
function decrypt ($ciphertext, $password){
    
    $privkey_hash = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')             # initialise 256 bit hashing algorithm
    $privkey = $privkey_hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($password))     # convert 256 bit hash into private key

    $cipher = New-Object System.Security.Cryptography.AesCryptoServiceProvider       # create new cipher object
    $cipher.key = $privkey                                                           # set the private key

    $ciphertext_bytes = [system.convert]::FromBase64String($ciphertext)                        # converts base64 ciphertext string into byte array
    $cipher.iv = $ciphertext_bytes[0..15]                                                      # get 128 bit salt from string
                                                                  
    $cipher_mode = $cipher.CreateDecryptor()                                         # create decryptor
    
    #decrypt with aes 
    

    $block_size = $ciphertext_bytes.Length                                                     # calculates length of byte array
    $plaintext_bytes = $cipher_mode.TransformFinalBlock($ciphertext_bytes, 16, $block_size - 16)     # transformation function for decryption
    $cipher.Dispose()                                                                          # frees up resources

    $plaintext = [System.Text.Encoding]::UTF8.GetString($plaintext_bytes)            # converts plaintext byte array into UTF-8 string
    return $plaintext

}
<#
Syntax

$ciphertext = encrypt ("this is a secret")("password1234")("00000000")
[console]::Write("`n`n$ciphertext`n`n")
$ciphertext = decrypt ("3Ush6e9x4SkRg6RrkTrm8op9Gu4qhClMiaF8RVWM9gTWTrkPHtmrsBoOwZiUQozJ")("password1234")
[console]::Write("`n`n$ciphertext`n`n")
#>

# set cursor coordinates
function cursor-goto-fine ([int] $x_coordinate, [int] $y_coordinate){                   
    [Console]::SetCursorPosition($x_coordinate, $y_coordinate);
}

function selection ([string] $name, [int] $index){
    cls;
    [console]::Write($name)

    if ($name -match '\.txt$'){
        return 1                                    # enter file
    } 
    else {
        if ($index -eq 0){
            return 99                               # exit dir
        }
        return 0                                    # enter dir
    }



}


# ANSI color code
$esc = "$([char]27)"
$reset = "$esc[0m"

$time = [System.Diagnostics.Stopwatch]::StartNew()

## Menu spacing parameters
$offset_x = 4
$offset_y = 4
$maxlengthname = 15
$maxlengthlength = 6


<#
$rootpath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\') # gets root path

function pathchecker ($base, $filepath) {                                                 # absolute path?
  if (Split-Path $filepath -IsAbsolute) { return $filepath }
  else { return "$base\$filepath" }
}
#>

# Window UI settings
$uisettings = (get-host).UI.RawUI
[string] $titlename = "Passwordtext v0.3"
$uisettings.WindowTitle = $titlename # apply window name title changes
$uisettings.CursorSize = 0 # hide flashing cursor
$current_size = $uisettings.WindowSize
$max_size = $uisettings.MaxPhysicalWindowSize

#init usable lines
$window_width = $current_size.width 
$window_height = $current_size.Height
cursor-goto-fine($window_width - 15)(1) # DEBUG
            [console]::Write("    - $window_width x $window_height") # DEBUG
$usable_lines = $window_height - $offset_y - 2
cursor-goto-fine(0)(0) # DEBUG
$time_last_windowcheck = $time.elapsed.totalseconds

function header {
    cursor-goto-fine(0)(0)
    [console]::Write("`n$esc[32m$titlename$reset by koh-gt`nEncrypt and decrypt your text files using SHA256.`n`n")
}

function ui ([int]$offset_x, [int]$offset_y, [int]$startindex, [int]$endindex){  #startindex and endindex unused for now
    
    $adultitems = (Get-ChildItem -Directory | Select Name)
    [int] $adultitems_count = ($adultitems | Measure).count
    $childitems = (Get-ChildItem *.txt | Select Name, Length)
    [int] $childitems_count = ($childitems | Measure).count                # $childitems.count returns nothing when there is only 1 element

    $totalitems_count = 1 + $adultitems_count + $childitems_count

    #find longest name string and filesize string length
    ## maxlength used - in childitems
    if ($adultitems_count -eq 1) {
        $itemlengthchecker_name = [string]($adultitems.Name).length
        if ($itemlengthchecker_name -gt $maxlengthname) {$maxlengthname = $itemlengthchecker_name}
    } else {
        for ($i= 0; $i -lt $adultitems_count; $i++){
            $itemlengthchecker = $adultitems[$i]
            $itemlengthchecker_name = ([string]$itemlengthchecker.Name).length
            if ($itemlengthchecker_name -gt $maxlengthname) {$maxlengthname = $itemlengthchecker_name}
        }
    }
    if ($childitems_count -eq 1) {
        $itemlengthchecker_name = [string]($childitems.Name).length
        $itemlengthchecker_length = [string]($childitems.length).length
        if ($itemlengthchecker_name -gt $maxlengthname) {$maxlengthname = $itemlengthchecker_name}
        if ($itemlengthchecker_length -gt $maxlengthlength) {$maxlengthlength = $itemlengthchecker_length}
    } else {
            for ($i= 0; $i -lt $childitems_count; $i++){
            $itemlengthchecker = $childitems[$i]
            $itemlengthchecker_name = ([string]$itemlengthchecker.Name).length
            $itemlengthchecker_length = ([string] $itemlengthchecker.length).length
            if ($itemlengthchecker_name -gt $maxlengthname) {$maxlengthname = $itemlengthchecker_name}
            if ($itemlengthchecker_length -gt $maxlengthlength) {$maxlengthlength = $itemlengthchecker_length}
        }
    }

    # initialise TUI
    ## initialise string array
    $tui_init_names = New-object string[] $totalitems_count
    $tui_init_string = New-object string[] $totalitems_count
    $tui_init_names[0] = "..."
    $tui_init_string[0] = " "*$offset_x + "..."

    ## fill array - adultitems

    if ($adultitems_count -eq 1){
        $item_name = [string] $adultitems.Name
        $tui_init_names[1] = $item_name
        $tui_init_string[1] = " "*$offset_x + $item_name
    } else {
        for ($i = 0; $i -lt $adultitems_count; $i++){
            $item_name = [string] $adultitems[$i].Name  
            $tui_init_names[$i + 1] = $item_name
            $tui_init_string[$i + 1] = " "*$offset_x + $item_name
        }
    }

    ## fill array - childitems
    if ($childitems_count -eq 1){
        $item_name = [string] $childitems.Name
        $item_length = [string] $childitems.length
        $tui_init_names[$adultitems_count + 1] = $item_name
        $tui_init_string[$adultitems_count + 1] = " "*$offset_x + $item_name + " "*($name_spacing + $length_spacing + 1) + $item_length
    } else {
        for ($i = 0; $i -lt $childitems_count; $i++){
            $item_name = [string] $childitems[$i].Name
            $item_length = [string] $childitems[$i].length                # is not the same as $childitems.length[$i] which gives 2 when there are 2 objects and no value for .length[1] or higher
            $name_spacing = $maxlengthname - $item_name.length
            $length_spacing = $maxlengthlength - $item_length.length
            $tui_init_names[$i + $adultitems_count + 1] = $item_name
            $tui_init_string[$i + $adultitems_count + 1] = " "*$offset_x + $item_name + " "*($name_spacing + $length_spacing + 1) + $item_length
        }
    }
    cursor-goto-fine(0)($offset_y)
    

    return @($tui_init_string, $tui_init_names)
    
}

function draw([int]$y, [string[]]$tui_init_string){
    
    $esc = "$([char]27)"
    $reset = "$esc[0m"
    cursor-goto-fine(0)($y)
    [console]::Write($tui_init_string -join "`n$reset")
    
}

function ui-draw-select([int]$x, [int]$y, [string[]]$ui_names,[int]$index){

    $esc = "$([char]27)"
    $reset = "$esc[0m"

    # initial highlight selection
    cursor-goto-fine($x)($y + $index)
    [Console]::Write("$esc[30;47m" + $ui_names[$index] + $reset)
    cursor-goto-fine(0)(0)

}

function ui-clean-select([int]$x, [int]$y, [string[]]$ui_names,[int]$index){ 
    
    # initial highlight selection
    cursor-goto-fine($x)($y + $index)
    [Console]::Write($ui_names[$index])
    cursor-goto-fine(0)(0)

}

function ui-select([int]$x, [int]$y, [string[]]$ui_names,[int]$oldindex, [int]$newindex){

    # cleanup old position
    ui-clean-select($x)($y)($ui_names)($oldindex)
    
    ui-draw-select($x)($y)($ui_names)($newindex)
    
    return $newindex
}

$selection_not_done = $true
$index_cleanup = 0
$index = 0
$performance_timer = 0

$output_array = ui($offset_x)($offset_y)($index)($window_height - 5)
$output = $output_array[0]
$names = $output_array[1]
$output_num = $output.length


header
draw($offset_y)($output)
ui-draw-select($offset_x)($offset_y)($names)($index)

while ($selection_not_done) {

    # wait for keys
    if ([console]::KeyAvailable) {
        $pressed = [system.console]::ReadKey()
        Switch ($pressed.key){
            W {$index--}
            S {$index++}
            A {}
            D {}
            UpArrow {$index--}
            DownArrow {$index++}
            LeftArrow {}
            RightArrow {}
            
            Enter {$choice = selection($names[$index])($index)
                Switch ($choice){
                    0 {}
                    1 {}
                    2 {}
                    3 {}
                    99 {}
                }
            }
            
        }
        cursor-goto-fine(0)(0)
    }

    
    
    # index within bounds checker
    if ($index -lt 0) {$index = 0}
    if ($index -ge $output_num){$index = $output_num - 1}

    if ($index -ne $index_cleanup){
        ui-select($offset_x)($offset_y)($names)($index_cleanup)($index)
        $index_cleanup = $index
    }
    

    
    # periodic only

    $time_now = $time.elapsed.totalseconds
    
    ## window resizing fix
    if ($time_now -gt $time_last_windowcheck + 0.1){
        $window_size_now = (get-host).UI.RawUI.WindowSize
        $window_width_now, $window_height_now = $window_size_now.Width, $window_size_now.Height
        
        if (($window_width_now -ne $window_width) -or ($window_height_now -ne $window_height)){

            cls;
            header
            draw($offset_y)($output)
            ui-draw-select($offset_x)($offset_y)($names)($index)

            
            $window_width, $window_height = $window_width_now, $window_height_now

            cursor-goto-fine($window_width - 15)(1) # DEBUG
            [console]::Write("$performance_timer - $window_width x $window_height") # DEBUG
            $usable_lines = $window_height - $offset_y - 2
            cursor-goto-fine(0)(0) # DEBUG

            $window_width = $window_width_now
            $window_height = $window_height_now
        }
        $time_last_windowcheck = $time.elapsed.totalseconds
        $performance_timer = 0

    }
    $performance_timer++
    
    
    
    
    
}




$file_open = Read-Host "`nPress Enter to continue..."


$a = Read-Host "Press Enter to continue..."




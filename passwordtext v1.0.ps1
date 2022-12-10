
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

    if ($name -match '\.txt$'){
        return 1                                    # enter file
    } 
    else {
        if ($index -eq 0){
            return 99                               # exit dir
        }
        return 0                                   # enter dir
    }

}

function get-path (){
    
    $rootpath = [string] ($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\')) # gets root path
    return $rootpath
}

function get-parent-path([string]$path){   
    if ($path -match '^[A-Z]{1}:\\$') {
        return $path
    } else {
        $ppath = Split-Path -Path $path -Parent
        return $ppath
    }
}

function get-nested-path ([string]$path, [string]$nest){
    if ($path -match '\.txt$'){                    # cant enter a file as a directory
        return $Path
    }
    if ($path -match '^[A-Z]{1}:\\$') {
        return "$path$nest"
    } else {
        return "$path\$nest"
    }
}

function pathchecker ($base, $filepath) {                                                 # absolute path? # not used
  if (Split-Path $filepath -IsAbsolute) { return $filepath }
  else { return "$base\$filepath" }
}


# Window UI settings
$version = "1.0"
$uisettings = (get-host).UI.RawUI
[string] $titlename = "Passwordtext v$version"
$uisettings.WindowTitle = $titlename # apply window name title changes



function header ([string]$path) {
    $esc = "$([char]27)"
    $reset = "$esc[0m"

    cursor-goto-fine(0)(0)
    [console]::Write("`n$esc[32m$titlename$reset by koh-gt. Encrypt and decrypt your text files using SHA256.`nPath: $path")

    return
}

function ui ([string]$Path, [int]$offset_x, [int]$offset_y, [int]$startindex, [int]$endindex){  #startindex and endindex unused for now
    
    $adultitems = (Get-ChildItem -Path $path -Directory | Select Name)
    [int] $adultitems_count = ($adultitems | Measure).count
    $childitems = (Get-ChildItem -path $path *.txt | Select Name, Length)
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
        $name_spacing = $maxlengthname - $item_name.length
        $length_spacing = $maxlengthlength - $item_length.length
        $tui_init_names[$adultitems_count + 1] = $item_name
        $tui_init_string[$adultitems_count + 1] = " "*$offset_x + $item_name + " "*($name_spacing + $length_spacing + 3) + $item_length
    } else {
        for ($i = 0; $i -lt $childitems_count; $i++){
            $item_name = [string] $childitems[$i].Name
            $item_length = [string] $childitems[$i].length                # is not the same as $childitems.length[$i] which gives 2 when there are 2 objects and no value for .length[1] or higher
            $name_spacing = $maxlengthname - $item_name.length
            $length_spacing = $maxlengthlength - $item_length.length
            $tui_init_names[$i + $adultitems_count + 1] = $item_name
            $tui_init_string[$i + $adultitems_count + 1] = " "*$offset_x + $item_name + " "*($name_spacing + $length_spacing + 3) + $item_length
        }
    }
    cursor-goto-fine(0)($offset_y)

    $tui_init_clean = @(" "*($offset_x+$maxlengthname+$maxlengthlength+4)) * $totalitems_count
    

    return @($tui_init_string, $tui_init_names, $tui_init_clean)
    
}

function draw([int]$y, [string[]]$tui_init_string, [int]$usable_lines, [int]$index_offset){

    $start_view = $index_offset
    $end_view = $usable_lines + $index_offset
    
    $esc = "$([char]27)"
    $reset = "$esc[0m"
    cursor-goto-fine(0)($y)

    $tui_len = $tui_init_string.length
    if ($tui_len -le $usable_lines) {
        [console]::Write($tui_init_string -join "`n$reset")
    } else {
        $tui_new_string = $tui_init_string[$start_view..$end_view]
        [console]::Write($tui_new_string -join "`n$reset")
    }
    
    return

}

function ui-draw-select([int]$x, [int]$y, [string[]]$ui_names,[int]$index, [int]$offsetindex){

    $esc = "$([char]27)"
    $reset = "$esc[0m"

    # initial highlight selection
    cursor-goto-fine($x)($y + $index - $offsetindex)
    [Console]::Write("$esc[30;47m" + $ui_names[$index] + $reset)
    cursor-goto-fine(0)(0)

    return

}

function ui-clean-select([int]$x, [int]$y, [string[]]$ui_names,[int]$index, [int]$offsetindex){ 
    
    # initial highlight selection
    cursor-goto-fine($x)($y + $index - $offsetindex)
    [Console]::Write($ui_names[$index])
    cursor-goto-fine(0)(0)

    return

}

function ui-select([int]$x, [int]$y, [string[]]$ui_names,[int]$oldindex, [int]$newindex, [int]$offsetindex){

    # cleanup old position
    ui-clean-select($x)($y)($ui_names)($oldindex)($offsetindex)
    
    ui-draw-select($x)($y)($ui_names)($newindex)($offsetindex)
    
    return $newindex
}


function menu ([string] $Path){
    cls;
    $uisettings = (get-host).UI.RawUI
    $uisettings.CursorSize = 0 # hide flashing cursor
    $current_size = $uisettings.WindowSize
    $max_size = $uisettings.MaxPhysicalWindowSize

    # ANSI color code
    $esc = "$([char]27)"
    $reset = "$esc[0m"

    $time = [System.Diagnostics.Stopwatch]::StartNew()

    ## Menu spacing parameters
    $offset_x = 4
    $offset_y = 4
    $maxlengthname = 15
    $maxlengthlength = 6

    # init usable lines
    $window_width = $current_size.width 
    $window_height = $current_size.Height
    cursor-goto-fine($window_width - 15)(1) # DEBUG
    [console]::Write("    - $window_width x $window_height") # DEBUG
    $usable_lines = $window_height - $offset_y - 2
    cursor-goto-fine(0)(0) # DEBUG
    $time_last_windowcheck = $time.elapsed.totalseconds
    $time_last_perfcheck = $time.elapsed.totalseconds
    $time_last_windowadjust = $time.elapsed.totalseconds

    # indices
    
    $index_cleanup, $index, $index_usable_offset, $performance_timer, $window_adjusted = 0, 0, 0, 0, 0
    
    $output_array = ui($Path)($offset_x)($offset_y)($index)($window_height - 5)
    $output = $output_array[0]
    $names = $output_array[1]
    $clean_output = $output_array[2]
    $output_num = $output.length


    $usable_lines = $window_height - $offset_y - 2 # ui
    header($path) # shows path
    draw($offset_y)($output)($usable_lines)($index_usable_offset)
    ui-draw-select($offset_x)($offset_y)($names)($index)($index_usable_offset)

    $loop = 1
    $data_collected = 0
    while ($loop -eq 1) {

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
                LeftArrow { #exit out of directory
                    [string] $datachoice = 99; [string] $open_name = $names[$index]; $data_collected = 1;
                }
                RightArrow { #enter new directory
                    if (-not($index -eq 0)){[string] $datachoice = 0;[string] $open_name = $names[$index];$data_collected = 1;}
                }
                Enter {
                    [string] $datachoice = selection($names[$index])($index)
                    [string] $open_name = $names[$index]
                    $data_collected = 1
                }
            
            }
            cursor-goto-fine(0)(0)
            #$index_usable_offset ### DEBUG
        }

        # data collected ?
        if ($data_collected -eq 1) {$loop = 0}
        # index within bounds checker
        if ($index -lt 0) {$index = 0}
        if ($index -ge $output_num){$index = $output_num - 1}
        # index outside viewrange checker
        if ($index -gt $usable_lines + $index_usable_offset) {
            $index_usable_offset++
            draw($offset_y)($clean_output)($usable_lines)($index_usable_offset)
            draw($offset_y)($output)($usable_lines)($index_usable_offset)
        }
        if ($index -lt $index_usable_offset) {
            $index_usable_offset--
            draw($offset_y)($clean_output)($usable_lines)($index_usable_offset)
            draw($offset_y)($output)($usable_lines)($index_usable_offset)
        }

        # update selection
        if ($index -ne $index_cleanup){
            ui-select($offset_x)($offset_y)($names)($index_cleanup)($index)($index_usable_offset)
            $index_cleanup = $index
        }

        # periodic only
        $time_now = $time.elapsed.totalseconds
        ## window resizing fix
        if ($time_now -gt $time_last_windowcheck + 0.01){
            $window_size_now = (get-host).UI.RawUI.WindowSize
            $window_width_now, $window_height_now = $window_size_now.Width, $window_size_now.Height
        
            if (($window_width_now -ne $window_width) -or ($window_height_now -ne $window_height)){
            
                $usable_lines = $window_height - $offset_y - 2
                cls; 
                $time_last_windowadjust = $time.elapsed.totalseconds          
                $window_adjusted = 1                      
                $window_width, $window_height = $window_width_now, $window_height_now

                cursor-goto-fine($window_width - 15)(1) # DEBUG
                [console]::Write("$window_width x $window_height") # DEBUG
                cursor-goto-fine(0)(0) # DEBUG
            }
            $time_last_windowcheck = $time.elapsed.totalseconds
        }
        #update after window adjusted
        if ($window_adjusted -eq 1){
            if ($time_now -gt $time_last_windowadjust + 0.01) {
                cls;
                $usable_lines = $window_height - $offset_y - 2
                header
                draw($offset_y)($output)($usable_lines)($index_usable_offset)

                if (-not ($index - $index_usable_offset -gt $usable_lines )){
                    ui-select($offset_x)($offset_y)($names)($index_cleanup)($index)($index_usable_offset) #selection is within resized bounds
                }
                $window_adjusted = 0
            }
        }

        # performance timer
        if ($time_now -gt $time_last_perfcheck + 1){
            cursor-goto-fine($window_width - 15)(2) # DEBUG
            [console]::Write(" "*(6 - ([string]$performance_timer).length)+ "$performance_timer tps") # DEBUG
            cursor-goto-fine(0)(0) # DEBUG
            $performance_timer = 0
            $time_last_perfcheck = $time.elapsed.totalseconds

        }
        $performance_timer++   
    }  
    return @($datachoice, $open_name)   
}

function read-only([string]$path){

    cls;
    header($path)
    
    $data = Get-Content $path -Raw
    [console]::Write("$data")
    Read-Host "Press Enter to continue"

}

function execute-decrypt([string]$path, [int]$overwrite){

    cls;
    header($path)
    cursor-goto-fine(8)(4)
    if ($overwrite -eq 1){
        [console]::Write("The original encrypted file $esc[37;1m$esc[41mwill be replaced!$reset`n`n You can use Ctrl+C to exit Powershell safely.`n`n")
    } else {
        [console]::Write("The original encrypted file will $esc[37;1mnot$reset be replaced!`n`n You can use Ctrl+C to exit Powershell safely.`n`n")
    }
            $password = Read-Host '            Password:' -AsSecureString
    $p = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    $pp = [string]$p
    $data = Get-Content $path | Out-String

    #$plaintext = decrypt ($data)($pp)
    
    try {
    $plaintext = decrypt ($data)($pp)
    }
    <#
    catch [CryptographicException] {
        [console]::Write("Incorrect password.`n`n")
        return
    } 
    #>
    catch {
        [console]::Write("The password is incorrect or`nthe file is not encrypted`n")
        Start-Sleep 1
        return
    }
    
    $newpath = $path #incomplete

    [console]::Write("$plaintext")
    Read-Host "`n`nPress Enter to continue"
    if($overwrite -eq 1){$plaintext | Out-File -FilePath "$newpath"}

}

function execute-encrypt([string]$path){

    cls;
    header($path)
    cursor-goto-fine(8)(4)
    # ANSI color code
    $esc = "$([char]27)"
    $reset = "$esc[0m"

    [console]::Write("The original unencrypted file $esc[37;1m$esc[41mwill be replaced!$reset`n        You will be prompted to enter your password twice`n        to ensure that the passwords match.`n`n You can use Ctrl+C to exit Powershell safely.`n`n")
            $password = Read-Host '            Password:' -AsSecureString
    $confirm_password = Read-Host '    Confirm Password:' -AsSecureString
            $p = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
            $pp = [string]$p
            $q = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm_password))
            $qq = [string]$q
    if($pp -cmatch $qq){
        $p, $q, $qq = $null, $null, $null
        $data = Get-Content $path | Out-String
        [string[]]$a = @(1..128)
        for ($i = 0; $i -lt 128; $i++){
            $a[$i] = Get-Random
        }
        $b = $a -join ""
        $ciphertext = encrypt ($data)($pp)($b)
        $pp = $null
        $password = $null
        $confirm_password = $null
        $newpath = $path #incomplete
        $ciphertext | Out-File -FilePath "$newpath"

    } else {
        
        [console]::Write("`n Passwords do not match. Exiting...`n")
        
        start-sleep 1
    }

}

function execute-action([int] $action, [string] $path){
    
    Switch ($action){
        0 {execute-encrypt($path)}           # encrypt permanently
        1 {execute-decrypt($path)(1)}        # decrypt permanently
        2 {execute-decrypt($path)(0)}        # decrypt temporarily
        3 {return}        # menu
        4 {read-only($path)}        # readonly
        5 {}        # duplicate
        6 {}        # edit
        7 {}        # delete
    }
    return
}

function menu-actions([string]$path, [string]$filename){

    # ANSI color code
    $esc = "$([char]27)"
    $reset = "$esc[0m"
    
    cls;
    $fullpath = get-nested-path($path)($filename)
    header($fullpath)
    $offset_x = 4
    $offset_y = 6

    # actions list
    [string[]]$actionstext = @("ENCRYPT PERMANENTLY SHA256","Permanently decrypt", "Temporarily decrypt and Read","...","Read only","Duplicate (WIP)","Edit (WIP)", "DELETE (WIP)")
    [int] $actionstext_length = $actionstext.length 

    [string[]]$actionslist = @(1..$actionstext_length)
    [string[]]$actionslistHL = @(1..$actionstext_length)

    for ($i = 1; $i -lt $actionstext_length; $i++){  
        $actionslist[$i] = " "*$offset_x + $actionstext[$i] + " "*(30 - ($actionstext[$i]).length)
        $actionslistHL[$i] = " "*$offset_x + "$esc[30;47m" + $actionstext[$i] + $reset + " "*(30 - ($actionstext[$i]).length)
    }
    $actionslist[0] = (" "*$offset_x + "$esc[31;1mENCRYPT WITH SHA256$reset")    # exceptions
    $actionslistHL[0] = (" "*$offset_x + "$esc[37;1m$esc[41mENCRYPT WITH SHA256$reset")    # exceptions
    $actionslist[1] = (" "*$offset_x + "$esc[36;1mPermanently decrypt$reset")    # exceptions
    $actionslistHL[1] = (" "*$offset_x + "$esc[37;1m$esc[46mPermanently decrypt$reset")    # exceptions

    # print actions list
    cursor-goto-fine($offset_x)($offset_y-2)
    [console]::Write("Select Action:")

    cursor-goto-fine(0)($offset_y)
    $actions = $actionslist -join "`n" 
    [console]::Write("$actions")

    # selector
    $loop = 1
    $data_collected = 0

    $index = 3 # middle
    $index_cleanup = $index
    cursor-goto-fine(0)($offset_y+$index)
    [console]::Write($actionslistHL[$index])
    cursor-goto-fine(0)(0)

    while ($loop -eq 1) {      
        # wait for keys
        if ([console]::KeyAvailable) {      
         
            $pressed = [system.console]::ReadKey()
            Switch ($pressed.key){
                W {$index--}
                S {$index++}
                UpArrow {$index--}
                DownArrow {$index++}            
                Enter {execute-action($index)($fullpath); $data_collected = 1}    
            }
            cursor-goto-fine(0)(0)
        }
        # data collected ?
        if ($data_collected -eq 1) {$loop = 0}
        # index within bounds checker
        if ($index -lt 0) {$index = 0}
        if ($index -ge $actionstext_length){$index = $actionstext_length - 1}
        # update selection
        if ($index -ne $index_cleanup){

            cursor-goto-fine(0)($offset_y+$index_cleanup)
            [console]::Write($actionslist[$index_cleanup])

            cursor-goto-fine(0)($offset_y+$index)
            [console]::Write($actionslistHL[$index])

            cursor-goto-fine(0)(0)
            $index_cleanup = $index
        }
    }
    
}

function main (){
    
    $looper = 1
    $path = get-path
    
    cls;  
    while ($looper -eq 1) {
        
        $menu_option = menu($path)
        $menu_option = $menu_option[-2,-1]
        $action, $filename = $menu_option[0], $menu_option[1]
        Switch ($action){
            0  { $path = get-nested-path($path)($filename) }
            99 { $path = get-parent-path($path) }
            1  { menu-actions($path)($filename) }

        } 
    }
}

main

#>

cursor-goto-fine (50)(3)

start-sleep 30
#$file_open = Read-Host "`nPress Enter to continue..."


#$a = Read-Host "Press Enter to continue..."




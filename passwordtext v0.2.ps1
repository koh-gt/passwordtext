
<#
# generate the private key
$password = "password"
$privkey_hash = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
$privkey = $privkey_hash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($password))
$privkey_string = [System.BitConverter]::ToString($privkey)
$privkey_string = $privkey_string.replace("-","")

[console]::Write("AAA`n$privkey_string`n")
#>

# encrypt
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

# decrypt
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

$ciphertext = encrypt ("this is a secret")("password1234")("00000000")
[console]::Write("`n`n$ciphertext`n`n")
$ciphertext = decrypt ("3Ush6e9x4SkRg6RrkTrm8op9Gu4qhClMiaF8RVWM9gTWTrkPHtmrsBoOwZiUQozJ")("password1234")
[console]::Write("`n`n$ciphertext`n`n")

$a = Read-Host "Press Enter to continue..."




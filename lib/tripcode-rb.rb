module TripcodeRb

  ## Required for secure tripcode
  require 'digest/md5'
  require 'base64'

  ## tripcode_from(str)

  ## Generate tripcode from string (e.g. author name)
  ## 'author!tripfag' -> 'IAt9l89O8w'

  ## @param str - string with tripcode (starts with ! or #)
  ## @param options:
  ##   string randomseed - randomseed for secure tripcode
  ##     ( secure tripcode will be disabled if randomseed is nil or false )
  ## @return tripcode

  ## Kusaba calculateNameAndTripcode() was used (ported?).
  ## Kusaba X imageboard engine, http://kusabax.cultnet.net/

  def tripcode_from(str, options={})

    tripcode = nil


    if str =~ /(#|!)(.*)/
      delimiter = $1
      cap = $2

      reordered_cap = cap.encode('SJIS', 'UTF-8')
      cap = reordered_cap unless reordered_cap.empty?


      if cap =~ /(.*?)(?:#{delimiter})(.*+)/
        cap = $1
        cap_secure = $2
        is_secure_trip = true
      else
        is_secure_trip = false
      end


      if cap && !cap.empty?
        cap.tr!('&amp;', '&')
        cap.tr!('&#44;', ', ')

        salt = "#{cap}H."[1..2]
        salt.gsub!(/[^\.-z]/, '.')
        salt.tr!(':;<=>?@[\\]^_`', 'ABCDEFGabcdef')
        tripcode = cap.crypt(salt)[-10..-1]
      end

    end


    # Generate secure tripcode if needed

    if is_secure_trip && options[:randomseed]
      unless cap.empty?
        tripcode = "#{tripcode}!"
      end

      secure_tripcode = Digest::MD5.hexdigest("#{cap_secure}#{options[:randomseed]}")
      secure_tripcode = Base64::encode64(secure_tripcode)
      # str_rot13 ?
      secure_tripcode = secure_tripcode[2..10]
      tripcode = "#{tripcode}!#{secure_tripcode}"
    end


    tripcode
  end

end

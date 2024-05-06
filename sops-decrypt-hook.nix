{sopsFiles}: {
  shellHook = ''
    for sopsFile in ${toString sopsFiles}; do
      if [ -f "$sopsFile" ]; then
        echo "Decrypting $sopsFile"
        while IFS= read -r line; do
          if [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*=.*$ ]]; then
            key=$(echo "$line" | cut -d '=' -f 1)
            value=$(echo "$line" | cut -d '=' -f 2)
            export $key="$value"
          fi
        done < <(sops --decrypt $sopsFile)
      fi
    done
  '';
}

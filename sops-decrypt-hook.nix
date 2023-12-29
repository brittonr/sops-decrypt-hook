{ sopsFile }: {
  shellHook = ''
    if [ -f ${sopsFile} ]; then
      while IFS= read -r line; do
        if [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*:.*$ ]]; then
          key=$(echo "$line" | cut -d ':' -f 1)
          value=$(echo "$line" | cut -d ':' -f 2- | sed 's/^ *//')
          export $key="$value"
        fi
      done < <(sops -d ${sopsFile})
    fi
  '';
}

with open('sample.pcap', 'rb') as f:
    data = f.read()

# 24 bajty nagłówka globalnego + pierwsza pełna ramka (około 100 bajtów)
# Następnie obcinamy plik w połowie drugiego pakietu
if len(data) > 150:
    # Bierzemy nagłówek globalny + pakiet 1 + tylko 5 bajtów z pakietu 2
    corrupted_data = data[:150]
else:
    # Jeśli plik jest mały, obcinamy w połowie pierwszego pakietu
    corrupted_data = data[:30]

with open('corrupted.pcap', 'wb') as f:
    f.write(corrupted_data)

print("Wygenerowano plik ze zniekształconą ramką!")
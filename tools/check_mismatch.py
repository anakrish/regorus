import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
count = 0
for provider in data:
    ns = provider['namespace']
    for rt in provider.get('resourceTypes', []):
        fq = ns + '/' + rt['resourceType']
        prefix = fq + '/'
        for a in rt.get('aliases', []):
            name = a['name']
            dp = a.get('defaultPath','')
            if not dp:
                continue
            alias_short = name[len(prefix):] if name.lower().startswith(prefix.lower()) else None
            if alias_short is None:
                continue
            arm_short = dp[len('properties.'):] if dp.startswith('properties.') else dp
            if alias_short.lower() != arm_short.lower():
                count += 1
                if count <= 5:
                    print(name)
                    print('  alias: ' + alias_short)
                    print('  arm:   ' + arm_short)
print('Total mismatches: ' + str(count))

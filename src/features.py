def add_timing_features(df):
    df_feat = df.copy()
    BEACON_INTERVAL = 60
    df_feat['timing_distance_from_60s'] = (
        df_feat['inter_event_seconds'] - BEACON_INTERVAL
    ).abs()
    return df_feat


def add_port_features(df):
    df_feat = df.copy()
    TOP_N_PORTS = 10
    common_ports = (
        df_feat['dst_port']
        .value_counts()
        .head(TOP_N_PORTS)
        .index
    )
    df_feat['is_rare_port'] = (~df_feat['dst_port'].isin(common_ports)).astype(int)
    return df_feat

def add_process_features(df):
    df_feat = df.copy()
    df_feat['proc_name_norm'] = (
        df_feat['proc_name']
        .fillna('unknown')
        .str.lower()
    )
    high_risk_procs = {
        'powershell.exe',
        'cmd.exe',
        'rundll32.exe',
        'regsvr32.exe',
        'mshta.exe',
        'wscript.exe',
        'cscript.exe',
        'meterpreter.exe',
        'sliver-client.exe',
        'unknown.bin'
    }

    # Low-risk processes (common user applications)
    low_risk_procs = {
        'chrome.exe',
        'firefox.exe',
        'msedge.exe',
        'outlook.exe',
        'word.exe',
        'excel.exe',
        'teams.exe',
        'zoom.exe',
        'slack.exe',
        'onedrive.exe',
        'spotify.exe'
    }
    df_feat['process_risk_score'] = 1
    df_feat.loc[
        df_feat['proc_name_norm'].isin(high_risk_procs),
        'process_risk_score'
    ] = 2
    df_feat.loc[
        df_feat['proc_name_norm'].isin(low_risk_procs),
        'process_risk_score'
    ] = 0

    return df_feat

def add_geoip_features(df):
    df_feat = df.copy()
    df_feat['country_code_norm'] = (
        df_feat['country_code']
        .fillna('UNKNOWN')
        .str.upper()
    )
    low_risk_countries = {
        'US', 'CA', 'GB', 'DE', 'FR', 'NL', 'JP', 'IN'
    }
    high_risk_countries = {
        'CN', 'RU', 'IR', 'TR', 'UA', 'NG', 'BR', 'HK', 'VN'
    }
    df_feat['geoip_risk_bucket'] = 1

    df_feat.loc[
        df_feat['country_code_norm'].isin(low_risk_countries),
        'geoip_risk_bucket'
    ] = 0

    df_feat.loc[
        df_feat['country_code_norm'].isin(high_risk_countries),
        'geoip_risk_bucket'
    ] = 2

    return df_feat

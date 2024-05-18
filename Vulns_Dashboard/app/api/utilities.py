import plotly.express as px
import plotly.io as pio
import plotly.graph_objects as go
from flask import current_app
from app.extensions import mongo

def get_softwares_clt():
    """
    Helper function to get the softwares collection
    """
    softwares_collection = current_app.config['CONTAINER_SOFTWARES']
    return mongo.db[softwares_collection]

def get_machines_clt():
    """
    Helper function to get the machines collection
    """
    machines_collection = current_app.config['CONTAINER_MACHINES']
    return mongo.db[machines_collection]

def chart_top_ten_vulnerable_softwares():
    """
    Create a pie chart with the top ten softwares with more vulnerabilities
    the top ten softwares are sorted by the number of vulnerabilities and its calculated with 
    the field 'totalVulnerabilities' in the database
    The average number of vulnerabilities is represented with a dashed red line
    Args: None
    Returns: JSON representation of the plot
    """
    softwares_clt = get_softwares_clt()
    
    # Get all softwares with vulnerabilities sorted by totalVulnerabilities field
    softwares_sorted = list(softwares_clt.find({'vulnerabilities': {'$not': {'$size': 0}}}, {'_id': 0}).sort('totalVulnerabilities', -1))
    top_softwares = softwares_sorted[:6]
    
    # Create a json of a software with the rest of the softwares named 'Others' and the sum of their totalVulnerabilities
    others = {
        'name': 'Others',
        'totalVulnerabilities': sum([s['totalVulnerabilities'] for s in softwares_sorted[6:]])
    }
    top_softwares.append(others)
    
    names = [s['name'] for s in top_softwares]
    vulnerabilities = [s['totalVulnerabilities'] for s in top_softwares]
    
    # Create pie chart using Plotly
    fig = px.pie(names=names, values=vulnerabilities)

    # Return the JSON representation of the plot
    return pio.to_json(fig)

def get_vulnerable_softwares():
    """
    Get all softwares with vulnerabilities in the database
    Args: None
    Returns: A list of softwares with vulnerabilities    
    """
    softwares_clt = get_softwares_clt()
    vulnerable_softwares = softwares_clt.find({'vulnerabilities': {'$not': {'$size': 0}}}, {'_id': 0})
    return list(vulnerable_softwares)

def impact_vulnerabilities(vulnerable_softwares):
    """
    Create a chart of horizontal bars with the impact of all vulnerabilities (low, medium, high, critical)
    Args: 
        vulnerable_softwares (list): List of software vulnerabilities
    Returns: 
        JSON representation of the plot
    """
    impact = { 
        'UNKNOWN': 0,
        'LOW': 0,
        'MEDIUM': 0,
        'HIGH': 0,
        'CRITICAL': 0
    }
    
    for software in vulnerable_softwares:
        for vulnerability in software['vulnerabilities']:
            severity = "UNKNOWN"
            if 'baseSeverity' in vulnerability['metrics']:
                severity = vulnerability['metrics']['baseSeverity']
            if severity in impact:
                impact[severity] += 1
            else:
                impact[severity] += 1

    # Define colors for the bars
    colors = ['#475387', '#edc40c', '#ed6d0c', '#c90e0e', '#111111']
    
    # Create horizontal bar chart using Plotly
    fig = go.Figure(go.Bar(
        y=list(impact.keys()),
        x=list(impact.values()),
        text=list(impact.values()),
        textposition='auto',
        marker_color=colors,
        orientation='h'
    ))

    # Update layout
    fig.update_layout(
        xaxis_title="Number of vulnerabilities",
        yaxis_title="Impact"
    )

    # Return JSON representation of the plot
    return fig.to_json()

def recent_vulnerabilities_qty(current_year):
    """
        Get the number of vulnerabilities in the current year (2024)
        For each vulnerability in a sofwares, check if the CVE ID contains the current year
        Args: current_year (str): Current year
        Returns: Quantity of vulnerabilities in the current year
    """
    softwares_clt = get_softwares_clt()
    if current_year == None:
        return 0
    current_year = current_year.strip()
    if len(current_year) != 4:
        return 0
    
    recent_vulns = 0
    try:
        #software list with vulnerabilities that have been published in the current year
        softwares = list(softwares_clt.find({'vulnerabilities.CVE_ID': {'$regex': current_year}}, {'_id': 0, 'vulnerabilities': 1}))
        for software in softwares:
            for vulnerability in software['vulnerabilities']:
                if current_year in vulnerability['CVE_ID']:
                    recent_vulns += 1
    except Exception as e:
        print("Error getting the recent vulnerabilities",e)
        
    return recent_vulns

def most_vulnerable_machine():
    """
        Get the machine with the most vulnerabilities
        First get a list with the id in machine JSON
        Then for each machine, get the number of softwares vulnerable with that id in the field list  associatedMachines
        Args: None
    """
    softwares_clt = get_softwares_clt()
    machines_clt = get_machines_clt()
    id_machines = []
    most_vulnerable_machine = {
        'id': 0,
        'vuln_softwares_qty': 0,
        'hostname': ""
    }
    try:
        id_machines = machines_clt.find({}, {'_id':0,'id': 1, 'hostname': 1})
        for id in id_machines:
            vuln_softwares_qty = softwares_clt.count_documents({'associatedMachines': id['id'], 'vulnerabilities': {'$not': {'$size': 0}}})
            if vuln_softwares_qty > most_vulnerable_machine['vuln_softwares_qty']:
                most_vulnerable_machine['id'] = id['id']
                most_vulnerable_machine['vuln_softwares_qty'] = vuln_softwares_qty
                most_vulnerable_machine['hostname'] = id['hostname']
    except Exception as e:
        print("Error getting the id machines list",e)
        
    return most_vulnerable_machine

def qty_critical_vulns(vulnerable_softwares):
    """
        Get the number of critical vulnerabilities
        For each vulnerability in a sofwares, check if the severity is critical
        in the field of the software ['vulnerabilities'][item_position]['metrics']['baseSeverity']
        Args: vulnerable_softwares (list): List of softwares with vulnerabilities
        Returns: Number of critical vulnerabilities
    """
    critical_vulns = 0
    for software in vulnerable_softwares:
        for vulnerability in software['vulnerabilities']:
            if 'baseSeverity' in vulnerability['metrics']:
                if vulnerability['metrics']['baseSeverity'] == 'CRITICAL':
                    critical_vulns += 1
                    
    return critical_vulns

def chart_top_ten_riskiest_vulnerabilities():
    """
    Create a chart of three vertical bars by vulnerability with the top ten vulnerabilities with more base score.
    The first bar is the base score, the second is exploitability score and the third is impact score.
    
    Args: None
    Returns: JSON representation of the plot
    """
    softwares_clt = get_softwares_clt()
    vulns_shorted_list = []
    try:
        vulns_list = list(softwares_clt.find({'vulnerabilities': {'$not': {'$size': 0}}},{'_id': 0, 'vulnerabilities': 1}))
    except Exception as e:
        print("Error getting the vulnerabilities list ",e)
        return
    
    for vulns in vulns_list:
        if 'vulnerabilities' not in vulns:
            continue
        for vuln in vulns['vulnerabilities']:
            baseScore = vuln['metrics'].get('baseScore', 0)
            exploitabilityScore = vuln['metrics'].get('exploitabilityScore', 0)
            impactScore = vuln['metrics'].get('impactScore', 0)
            vulnShortedJSON = {
                'CVE_ID': vuln['CVE_ID'],
                'baseScore': baseScore,
                'exploitabilityScore': exploitabilityScore,
                'impactScore': impactScore,
            }
            vulns_shorted_list.append(vulnShortedJSON)
    
    vulns_shorted_list.sort(key=lambda x: (x['baseScore'], x['impactScore'], x['exploitabilityScore']), reverse=True)
    top_ten_vulns = vulns_shorted_list[:10]
    
    # Create the chart specified in the function description
    cve_ids = [vuln['CVE_ID'] for vuln in top_ten_vulns]
    base_scores = [vuln['baseScore'] for vuln in top_ten_vulns]
    exploitability_scores = [vuln['exploitabilityScore'] for vuln in top_ten_vulns]
    impact_scores = [vuln['impactScore'] for vuln in top_ten_vulns]
    
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=cve_ids,
        y=base_scores,
        name='Base Score',
        marker_color='#d00000'
    ))
    fig.add_trace(go.Bar(
        x=cve_ids,
        y=impact_scores,
        name='Impact Score',
        marker_color='#e85d04'
    ))
    fig.add_trace(go.Bar(
        x=cve_ids,
        y=exploitability_scores,
        name='Exploitability Score',
        marker_color='#ffba08'
    ))
    
    # Update layout
    fig.update_layout(
        xaxis_title="CVE IDENTIFIER",
        yaxis_title="SCORE",
        barmode='group',
        xaxis_tickangle=-45,
        yaxis=dict(range=[0, 13], tickmode='linear', tick0=1, dtick=1)
    )
    
    # Return JSON representation of the plot
    return pio.to_json(fig)
    
def qty_vulns_severity_across_time(vulnerable_softwares):
    """
    Create a chart with the number of vulnerabilities by severity across time.
    This function creates six lists:
    - list of years: the year is obtained from CVE ID in the field ['vulnerabilities'][item_position]['CVE_ID']
    - list of low vulnerabilities: this contains the quantity of low vulnerabilities by year
    - list of medium vulnerabilities: this contains the quantity of medium vulnerabilities by year
    - list of high vulnerabilities: this contains the quantity of high vulnerabilities by year
    - list of critical vulnerabilities: this contains the quantity of critical vulnerabilities by year
    - list of total vulnerabilities: this contains the total quantity of vulnerabilities by year
    Second, the function creates a chart with the six lists created before 
    where x axis is the year and y axis is the other lists.
    
    Args: 
        vulnerable_softwares (list): List of software vulnerabilities
    Returns: 
        JSON representation of the plot
    """
    
    # Lists to store the data
    years = []
    low_vulns = []
    medium_vulns = []
    high_vulns = []
    critical_vulns = []
    total_vulns = []
    
    # Get the data
    for software in vulnerable_softwares:
        if 'vulnerabilities' not in software:
            continue
        for vulnerability in software['vulnerabilities']:
            if 'baseSeverity' in vulnerability['metrics']:
                severity = vulnerability['metrics']['baseSeverity'] if 'baseSeverity' in vulnerability['metrics'] else 'UNKNOWN'
                year = vulnerability['CVE_ID'].split('-')[1]
                
                # Check if the year is already in the list, if not, add it
                if year not in years:
                    years.append(year)
                    low_vulns.append(0)
                    medium_vulns.append(0)
                    high_vulns.append(0)
                    critical_vulns.append(0)
                    total_vulns.append(0)
                years.sort()
                # Get the index of the year in the list
                year_index = years.index(year)
                total_vulns[year_index] += 1
                # Add the vulnerability to the corresponding list
                if severity == 'LOW':
                    low_vulns[year_index] += 1
                elif severity == 'MEDIUM':
                    medium_vulns[year_index] += 1
                elif severity == 'HIGH':
                    high_vulns[year_index] += 1
                elif severity == 'CRITICAL':
                    critical_vulns[year_index] += 1

    # Create the chart
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=years,
        y=low_vulns,
        mode='lines+markers',
        name='Low',
        line=dict(color='#e3d800', width=2),
        marker=dict(size=4)
    ))
    fig.add_trace(go.Scatter(
        x=years,
        y=medium_vulns,
        mode='lines+markers',
        name='Medium',
        line=dict(color='orange', width=2),
        marker=dict(size=4)
    ))
    fig.add_trace(go.Scatter(
        x=years,
        y=high_vulns,
        mode='lines+markers',
        name='High',
        line=dict(color='red', width=2),
        marker=dict(size=4)
    ))
    fig.add_trace(go.Scatter(
        x=years,
        y=critical_vulns,
        mode='lines+markers',
        name='Critical',
        line=dict(color='black', width=2),
        marker=dict(size=4)
    ))

    # Update layout
    fig.update_layout(
        xaxis_title="Year",
        yaxis_title="Number of Vulnerabilities",
        xaxis_tickangle=-45,
        yaxis=dict(tickmode='linear', tick0=0, dtick=2),
        plot_bgcolor='#EEEEEE'
    )
    
    # Return JSON representation of the plot
    return pio.to_json(fig)   

def donut_chart_machines_most_vuln():
    """
    Create a donut chart with the machines with the most vulnerabilities
    The first six machines with more vulnerabilities are selected for normal percentage
    and the rest of the machines are grouped in a single slice called 'Others'
    """
    softwares_clt = get_softwares_clt()
    machines_clt = get_machines_clt()
    
    list_machines = []
    try:
        id_machines = machines_clt.find({}, {'_id':0,'id':1,'hostname': 1})
        for id in id_machines:
            vuln_softwares_qty = softwares_clt.count_documents({'associatedMachines': id['id'], 'vulnerabilities': {'$not': {'$size': 0}}})
            list_machines.append(
                {
                    'id': id['id'],
                    'hostname': id['hostname'], 
                    'vuln_softwares_qty': vuln_softwares_qty
                }
            )
    except Exception as e:
        print("Error getting the id machines list",e)
        return
    
    list_machines.sort(key=lambda x: x['vuln_softwares_qty'], reverse=True)
    top_machines = list_machines[:9]
    others = {
        'id': 0,
        'hostname': 'Others',
        'vuln_softwares_qty': sum([m['vuln_softwares_qty'] for m in list_machines[9:]])
    }
    top_machines.append(others)
    
    hostnames = [m['hostname'] for m in top_machines]
    vulnerabilities = [m['vuln_softwares_qty'] for m in top_machines]
    
    fig = go.Figure(go.Pie(
        labels=hostnames,
        values=vulnerabilities,
        hole=0.6,
        textinfo='label+percent',
        insidetextorientation='radial'
    ))

    fig.update_layout(
        annotations=[dict(text='Machines', x=0.5, y=0.5, font_size=20, showarrow=False)]
    )
    
    return pio.to_json(fig)

def radial_chart_cves_version3():
    """
    Create a radial chart with all the vulnerabilities that have a CVSS version 3.0 or 3.1
    The radial chart is an octagon with the following values:
    - Attack Vector, possible values: Network (0.8), Adjacent (0.6), Local (0.4), Physical (0.2)
    - Attack Complexity, possible values: Low (0.8), High (0.4)
    - Privileges Required, possible values: None (0.8), Low (0.6), High (0.4)
    - User Interaction, possible values: None (0.85), Required (0.25)
    - Scope, possible values: Unchanged (0.85), Changed (0.25)
    - Confidentiality Impact, possible values: None (0.0), Low (0.4), High (0.8)
    - Integrity Impact, possible values: None (0.0), Low (0.4), High (0.8)
    - Availability Impact, possible values: None (0.0), Low (0.4), High (0.8)
    
    The radial chart has 4 r grids (0.2, 0.4, 0.6, 0.8)
    """
    values = {
        "attack_vector": {
            'NETWORK': 0.8,
            'ADJACENT': 0.6,
            'LOCAL': 0.4,
            'PHYSICAL': 0.2
        },
        "attack_complexity": {
            'LOW': 0.8,
            'HIGH': 0.4
        },
        "privileges_required": {
            'NONE': 0.8,
            'LOW': 0.6,
            'HIGH': 0.4
        },
        "user_interaction": {
            'NONE': 0.85,
            'REQUIRED': 0.25
        },
        "scope": {
            'UNCHANGED': 0.85,
            'CHANGED': 0.25
        },
        "confidentiality_impact": {
            'NONE': 0.0,
            'LOW': 0.4,
            'HIGH': 0.8
        },
        "integrity_impact": {
            'NONE': 0.0,
            'LOW': 0.4,
            'HIGH': 0.8
        },
        "availability_impact": {
            'NONE': 0.0,
            'LOW': 0.4,
            'HIGH': 0.8
        },
    }
    
    versions = ["3.0", "3.1"]
    softwares_clt = get_softwares_clt()
    vulns_softwares = list(softwares_clt.find({'vulnerabilities': {'$not': {'$size': 0}}}, {'_id': 0, 'vulnerabilities': 1}))
    vulns = []
    for software in vulns_softwares:
        for vulnerability in software['vulnerabilities']:
            if 'cvssDetailedData' not in vulnerability['metrics']:
                continue
            cvss_data = vulnerability['metrics']['cvssDetailedData']
            if cvss_data['version'] in versions:
                vulns.append(cvss_data)
    
    total_qty_vulns = len(vulns)
    if total_qty_vulns == 0:
        return pio.to_json(go.Figure())  # Return an empty figure if no data
    
    attack_vector = 0
    attack_complexity = 0
    privileges_required = 0
    user_interaction = 0
    scope = 0
    confidentiality_impact = 0
    integrity_impact = 0
    availability_impact = 0
    
    for vuln in vulns:
        if vuln['attackVector'] == "ADJACENT_NETWORK":
            vuln['attackVector'] = "ADJACENT"
        attack_vector += values['attack_vector'][vuln['attackVector']]
        attack_complexity += values['attack_complexity'][vuln['attackComplexity']]
        privileges_required += values['privileges_required'][vuln['privilegesRequired']]
        user_interaction += values['user_interaction'][vuln['userInteraction']]
        scope += values['scope'][vuln['scope']]
        confidentiality_impact += values['confidentiality_impact'][vuln['confidentialityImpact']]
        integrity_impact += values['integrity_impact'][vuln['integrityImpact']]
        availability_impact += values['availability_impact'][vuln['availabilityImpact']]
    
    attack_vector /= total_qty_vulns
    attack_complexity /= total_qty_vulns
    privileges_required /= total_qty_vulns
    user_interaction /= total_qty_vulns
    scope /= total_qty_vulns
    confidentiality_impact /= total_qty_vulns
    integrity_impact /= total_qty_vulns
    availability_impact /= total_qty_vulns
    
    categories = [
        'Attack Vector', 'Attack Complexity', 'Privileges Required', 
        'User Interaction', 'Scope', 'Confidentiality Impact', 
        'Integrity Impact', 'Availability Impact'
    ]
    
    values = [
        attack_vector, attack_complexity, privileges_required, 
        user_interaction, scope, confidentiality_impact, 
        integrity_impact, availability_impact
    ]
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatterpolar(
        r=values,
        theta=categories,
        fill='toself',
        name='CVSS v3.0/v3.1'
    ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 1],
                tickvals=[0.2, 0.4, 0.6, 0.8, 1.0]
            )
        ),
    )
    
    return pio.to_json(fig)

def get_total_vulnerabilities():
    softwares_clt = get_softwares_clt()
    pipeline = [
        {
            "$project": {
                "_id": 0,
                "listSize": { "$size": "$vulnerabilities" }
            }
        },
        {
            "$match": {
                "listSize": { "$ne": 0 }
            }
        }
    ]
    
    softwares_vuln = list(softwares_clt.aggregate(pipeline))
    total_vulnerabilities = sum(doc['listSize'] for doc in softwares_vuln)
    return total_vulnerabilities

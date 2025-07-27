#!/usr/bin/env python3
"""
AI Insights Endpoint - Provides intelligent binary analysis with web search
"""

import json
import asyncio
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_app.web_search import web_search

ai_insights_bp = Blueprint('ai_insights', __name__)

@ai_insights_bp.route('/api/ai/insights', methods=['POST'])
def get_ai_insights():
    """
    Get AI-powered insights about binary comparison with web research
    """
    try:
        data = request.get_json()
        context = data.get('context', {})
        include_web_search = data.get('includeWebSearch', False)
        search_queries = data.get('searchQueries', [])
        
        binary1 = context.get('binary1', 'Unknown Binary 1')
        binary2 = context.get('binary2', 'Unknown Binary 2')
        
        print(f"🤖 AI Insights requested for: {binary1} vs {binary2}")
        
        insights = {
            'timestamp': datetime.now().isoformat(),
            'binaryNames': {
                'binary1': binary1,
                'binary2': binary2
            }
        }
        
        # Perform web search if requested
        if include_web_search and search_queries:
            print(f"🌐 Performing web search with {len(search_queries)} queries...")
            
            search_results = []
            security_findings = []
            research_links = []
            
            for query in search_queries[:3]:  # Limit to 3 queries for performance
                try:
                    print(f"   🔍 Searching: {query}")
                    results = web_search(query)
                    search_results.extend(results)
                    
                    # Process results for security findings
                    for result in results:
                        title = result.get('title', '').lower()
                        snippet = result.get('snippet', '').lower()
                        
                        # Look for CVE mentions
                        if 'cve-' in title or 'cve-' in snippet:
                            cve_match = None
                            if 'cve-' in title:
                                import re
                                cve_match = re.search(r'cve-\d{4}-\d+', title)
                            
                            security_findings.append({
                                'title': result.get('title', 'Security Finding'),
                                'description': result.get('snippet', 'No description available')[:200],
                                'severity': 'high' if any(word in snippet for word in ['critical', 'high', 'severe']) else 'medium',
                                'cveId': cve_match.group(0).upper() if cve_match else None,
                                'source': result.get('url', '')
                            })
                        
                        # Look for research papers/reports
                        elif any(word in title for word in ['research', 'analysis', 'vulnerability', 'security']):
                            research_links.append({
                                'title': result.get('title', 'Research Resource'),
                                'description': result.get('snippet', 'No description available')[:150],
                                'url': result.get('url', '')
                            })
                
                except Exception as e:
                    print(f"   ❌ Search failed for '{query}': {e}")
                    continue
            
            # Add search results to insights
            if security_findings:
                insights['securityFindings'] = security_findings[:5]  # Limit to top 5
            
            if research_links:
                insights['researchLinks'] = research_links[:6]  # Limit to top 6
            
            print(f"   ✅ Found {len(security_findings)} security findings, {len(research_links)} research links")
        
        # Generate AI analysis based on structural data
        function_stats = context.get('functionStats', {})
        binary_metadata = context.get('binaryMetadata', {})
        
        analysis_summary = generate_analysis_summary(
            binary1, binary2, function_stats, binary_metadata, context
        )
        
        if analysis_summary:
            insights['versionAnalysis'] = analysis_summary
        
        # Generate AI recommendations
        recommendations = generate_recommendations(
            context, security_findings if include_web_search else []
        )
        
        if recommendations:
            insights['recommendations'] = recommendations
        
        print(f"✅ AI Insights generated successfully")
        return jsonify(insights)
        
    except Exception as e:
        print(f"❌ AI Insights error: {e}")
        return jsonify({
            'error': 'Failed to generate AI insights',
            'message': str(e)
        }), 500


def generate_analysis_summary(binary1, binary2, function_stats, binary_metadata, context):
    """Generate intelligent analysis summary"""
    try:
        summary_parts = []
        
        # Analyze function changes
        added_count = context.get('addedFunctions', 0)
        deleted_count = context.get('deletedFunctions', 0)
        modified_count = context.get('modifiedFunctions', 0)
        
        if added_count > deleted_count:
            summary_parts.append(f"The transition from {binary1} to {binary2} shows expansion with {added_count} new functions added and {deleted_count} removed, suggesting feature enhancements or new capabilities.")
        elif deleted_count > added_count:
            summary_parts.append(f"The update from {binary1} to {binary2} shows streamlining with {deleted_count} functions removed and {added_count} added, indicating optimization or feature removal.")
        else:
            summary_parts.append(f"The update shows balanced changes with {added_count} functions added and {deleted_count} removed, suggesting targeted improvements.")
        
        # Analyze binary size changes
        if binary_metadata.get('size_change'):
            size_change_kb = binary_metadata['size_change'] // 1024
            if size_change_kb > 0:
                summary_parts.append(f"Binary size increased by {size_change_kb}KB, likely due to new functionality or improved features.")
            else:
                summary_parts.append(f"Binary size decreased by {abs(size_change_kb)}KB, suggesting optimization or code removal.")
        
        # Analyze compatibility
        match_percentage = function_stats.get('match_percentage')
        if match_percentage:
            match_rate = float(match_percentage)
            if match_rate > 95:
                summary_parts.append("High structural compatibility indicates this is likely a minor version update with bug fixes or small enhancements.")
            elif match_rate > 80:
                summary_parts.append("Moderate structural changes suggest a significant update with new features or architectural improvements.")
            else:
                summary_parts.append("Substantial structural differences indicate a major version change or significant refactoring.")
        
        release_notes = []
        if modified_count > 0:
            release_notes.append(f"Modified {modified_count} existing functions for improvements or bug fixes")
        if added_count > 0:
            release_notes.append(f"Added {added_count} new functions for enhanced functionality")
        if deleted_count > 0:
            release_notes.append(f"Removed {deleted_count} deprecated or unnecessary functions")
        
        return {
            'summary': ' '.join(summary_parts),
            'releaseNotes': release_notes if release_notes else None
        }
        
    except Exception as e:
        print(f"Error generating analysis summary: {e}")
        return None


def generate_recommendations(context, security_findings):
    """Generate AI-powered recommendations"""
    try:
        recommendations = []
        
        added_count = context.get('addedFunctions', 0)
        modified_count = context.get('modifiedFunctions', 0)
        
        # Security recommendations
        if security_findings:
            high_severity_count = sum(1 for f in security_findings if f.get('severity') == 'high')
            if high_severity_count > 0:
                recommendations.append(f"🚨 CRITICAL: {high_severity_count} high-severity security findings detected. Prioritize security testing and consider postponing deployment until issues are resolved.")
            else:
                recommendations.append("🔍 Security findings detected. Review the identified vulnerabilities and assess their impact on your specific use case.")
        
        # Testing recommendations
        if added_count > 5:
            recommendations.append(f"🧪 TESTING FOCUS: With {added_count} new functions, conduct comprehensive integration testing to ensure new features work correctly with existing functionality.")
        
        if modified_count > 10:
            recommendations.append(f"🔄 REGRESSION TESTING: {modified_count} functions were modified. Perform thorough regression testing to ensure no existing functionality is broken.")
        
        # Performance recommendations
        binary_metadata = context.get('binaryMetadata', {})
        if binary_metadata.get('size_change', 0) > 100000:  # 100KB increase
            recommendations.append("📊 PERFORMANCE: Significant binary size increase detected. Monitor startup time, memory usage, and loading performance in production.")
        
        # Update strategy recommendations
        match_percentage = context.get('functionStats', {}).get('match_percentage')
        if match_percentage and float(match_percentage) < 85:
            recommendations.append("🔄 DEPLOYMENT: Low structural similarity suggests this is a major update. Plan for extended testing cycles and gradual rollout strategy.")
        
        # Documentation recommendations
        if added_count > 0 or modified_count > 0:
            recommendations.append("📚 DOCUMENTATION: Update user documentation and API references to reflect functional changes and new capabilities.")
        
        # Minimum recommendations if none generated
        if not recommendations:
            recommendations.append("✅ Structural analysis indicates a stable update. Follow standard testing procedures before deployment.")
            recommendations.append("🔍 Monitor system behavior post-deployment to ensure optimal performance.")
        
        return recommendations
        
    except Exception as e:
        print(f"Error generating recommendations: {e}")
        return ["Review the analysis results and follow standard security practices."] 
import React, { useEffect, useRef, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  CircularProgress,
  Alert,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  SelectChangeEvent,
  Chip,
  Stack
} from '@mui/material';
import {
  Download as DownloadIcon,
  ZoomIn as ZoomInIcon,
  ZoomOut as ZoomOutIcon,
  CenterFocusStrong as CenterIcon
} from '@mui/icons-material';
import { toast } from 'react-toastify';
import { apiClient } from '../utils/api';
import * as d3 from 'd3';

interface CFGNode {
  id: string;
  label: string;
  address: string;
  instructions: string[];
  x: number;
  y: number;
  type: 'entry' | 'exit' | 'basic' | 'conditional';
}

interface CFGEdge {
  source: string;
  target: string;
  type: 'fallthrough' | 'jump' | 'conditional';
}

interface CFGData {
  nodes: CFGNode[];
  edges: CFGEdge[];
  function_name: string;
  function_address: string;
}

interface CFGVisualizationProps {
  binaryId: string;
}

const CFGVisualization: React.FC<CFGVisualizationProps> = ({ binaryId }) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const [cfgData, setCfgData] = useState<CFGData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedFunction, setSelectedFunction] = useState<string>('');
  const [availableFunctions, setAvailableFunctions] = useState<string[]>([]);

  const drawCFG = (data: CFGData) => {
    if (!svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = 800;
    const height = 600;
    const nodeWidth = 120;
    const nodeHeight = 60;

    svg.attr('width', width).attr('height', height);

    // Add arrow marker definition
    const defs = svg.append('defs');
    defs.append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 8)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#666');

    const g = svg.append('g');

    // Create zoom behavior
    const zoomBehavior = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoomBehavior);

    // Add edges first (so they appear behind nodes)
    const edges = g.selectAll('.edge')
      .data(data.edges)
      .enter()
      .append('line')
      .attr('class', 'edge')
      .attr('x1', (d: CFGEdge) => {
        const source = data.nodes.find(n => n.id === d.source);
        return source ? source.x : 0;
      })
      .attr('y1', (d: CFGEdge) => {
        const source = data.nodes.find(n => n.id === d.source);
        return source ? source.y : 0;
      })
      .attr('x2', (d: CFGEdge) => {
        const target = data.nodes.find(n => n.id === d.target);
        return target ? target.x : 0;
      })
      .attr('y2', (d: CFGEdge) => {
        const target = data.nodes.find(n => n.id === d.target);
        return target ? target.y : 0;
      })
      .attr('stroke', (d: CFGEdge) => {
        switch (d.type) {
          case 'conditional': return '#ff6b6b';
          case 'jump': return '#4ecdc4';
          default: return '#666';
        }
      })
      .attr('stroke-width', 2)
      .attr('marker-end', 'url(#arrowhead)');

    // Add nodes
    const nodeGroups = g.selectAll('.node')
      .data(data.nodes)
      .enter()
      .append('g')
      .attr('class', 'node')
      .attr('transform', (d: CFGNode) => `translate(${d.x - nodeWidth/2}, ${d.y - nodeHeight/2})`);

    // Add node rectangles
    nodeGroups.append('rect')
      .attr('width', nodeWidth)
      .attr('height', nodeHeight)
      .attr('rx', 5)
      .attr('ry', 5)
      .attr('fill', (d: CFGNode) => {
        switch (d.type) {
          case 'entry': return '#4caf50';
          case 'exit': return '#f44336';
          case 'conditional': return '#ff9800';
          default: return '#2196f3';
        }
      })
      .attr('stroke', '#333')
      .attr('stroke-width', 2);

    // Add node labels
    nodeGroups.append('text')
      .attr('x', nodeWidth / 2)
      .attr('y', 20)
      .attr('text-anchor', 'middle')
      .attr('fill', 'white')
      .attr('font-size', '12px')
      .attr('font-weight', 'bold')
      .text((d: CFGNode) => d.label);

    // Add address labels
    nodeGroups.append('text')
      .attr('x', nodeWidth / 2)
      .attr('y', 35)
      .attr('text-anchor', 'middle')
      .attr('fill', 'white')
      .attr('font-size', '10px')
      .text((d: CFGNode) => d.address);

    // Add instruction count
    nodeGroups.append('text')
      .attr('x', nodeWidth / 2)
      .attr('y', 50)
      .attr('text-anchor', 'middle')
      .attr('fill', 'white')
      .attr('font-size', '9px')
      .text((d: CFGNode) => `${d.instructions.length} instr.`);

    // Add tooltips
    nodeGroups.append('title')
      .text((d: CFGNode) => 
        `${d.label}\nAddress: ${d.address}\nType: ${d.type}\nInstructions: ${d.instructions.length}\n\n${d.instructions.slice(0, 5).join('\n')}${d.instructions.length > 5 ? '\n...' : ''}`
      );

    // Add zoom controls
    const zoomIn = () => {
      svg.transition().call(zoomBehavior.scaleBy, 1.5);
    };

    const zoomOut = () => {
      svg.transition().call(zoomBehavior.scaleBy, 1 / 1.5);
    };

    const resetZoom = () => {
      svg.transition().call(zoomBehavior.transform, d3.zoomIdentity);
    };

    // Store zoom functions for button handlers
    (svg.node() as any)._zoomIn = zoomIn;
    (svg.node() as any)._zoomOut = zoomOut;
    (svg.node() as any)._resetZoom = resetZoom;
  };

  const fetchCFG = async (functionAddress: string) => {
    if (!functionAddress) return;

    setLoading(true);
    setError(null);

    try {
      const response = await apiClient.getCFG(binaryId, functionAddress);
      setCfgData(response);
      
      // Auto-layout nodes if they don't have positions
      if (response.nodes.some(node => !node.x || !node.y)) {
        layoutNodes(response);
      }
      
      drawCFG(response);
      toast.success('CFG loaded successfully');
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load CFG';
      setError(errorMessage);
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const layoutNodes = (data: CFGData) => {
    // Simple hierarchical layout
    const levels: { [key: string]: number } = {};
    const visited = new Set<string>();
    
    // Find entry node
    const entryNode = data.nodes.find(n => n.type === 'entry') || data.nodes[0];
    if (!entryNode) return;

    // BFS to assign levels
    const queue = [{ node: entryNode.id, level: 0 }];
    levels[entryNode.id] = 0;
    visited.add(entryNode.id);

    while (queue.length > 0) {
      const { node: nodeId, level } = queue.shift()!;
      
      data.edges
        .filter(e => e.source === nodeId)
        .forEach(edge => {
          if (!visited.has(edge.target)) {
            levels[edge.target] = level + 1;
            visited.add(edge.target);
            queue.push({ node: edge.target, level: level + 1 });
          }
        });
    }

    // Position nodes
    const levelGroups: { [level: number]: string[] } = {};
    Object.entries(levels).forEach(([nodeId, level]) => {
      if (!levelGroups[level]) levelGroups[level] = [];
      levelGroups[level].push(nodeId);
    });

    const nodeSpacing = 150;
    const levelSpacing = 100;

    Object.entries(levelGroups).forEach(([level, nodeIds]) => {
      const levelNum = parseInt(level);
      const startX = (800 - (nodeIds.length - 1) * nodeSpacing) / 2;
      
      nodeIds.forEach((nodeId, index) => {
        const node = data.nodes.find(n => n.id === nodeId);
        if (node) {
          node.x = startX + index * nodeSpacing;
          node.y = 100 + levelNum * levelSpacing;
        }
      });
    });
  };

  const downloadSVG = () => {
    if (!svgRef.current) return;

    const svgData = new XMLSerializer().serializeToString(svgRef.current);
    const svgBlob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
    const svgUrl = URL.createObjectURL(svgBlob);
    
    const downloadLink = document.createElement('a');
    downloadLink.href = svgUrl;
    downloadLink.download = `cfg_${cfgData?.function_name || 'function'}.svg`;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);
    URL.revokeObjectURL(svgUrl);
  };

  const handleFunctionChange = (event: SelectChangeEvent) => {
    const functionAddress = event.target.value;
    setSelectedFunction(functionAddress);
    fetchCFG(functionAddress);
  };

  const handleZoomIn = () => {
    const svg = svgRef.current;
    if (svg && (svg as any)._zoomIn) {
      (svg as any)._zoomIn();
    }
  };

  const handleZoomOut = () => {
    const svg = svgRef.current;
    if (svg && (svg as any)._zoomOut) {
      (svg as any)._zoomOut();
    }
  };

  const handleResetZoom = () => {
    const svg = svgRef.current;
    if (svg && (svg as any)._resetZoom) {
      (svg as any)._resetZoom();
    }
  };

  // Load available functions on component mount
  useEffect(() => {
    const loadFunctions = async () => {
      try {
        // This would typically come from an API endpoint that lists functions
        // For now, we'll use some example addresses
        setAvailableFunctions([
          '0x401000',
          '0x401100',
          '0x401200',
          '0x401300'
        ]);
      } catch (err) {
        console.error('Failed to load functions:', err);
      }
    };

    loadFunctions();
  }, [binaryId]);

  return (
    <Card>
      <CardContent>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
          <Typography variant="h6">Control Flow Graph</Typography>
          <Stack direction="row" spacing={1}>
            <Button
              startIcon={<ZoomInIcon />}
              onClick={handleZoomIn}
              disabled={!cfgData}
              size="small"
            >
              Zoom In
            </Button>
            <Button
              startIcon={<ZoomOutIcon />}
              onClick={handleZoomOut}
              disabled={!cfgData}
              size="small"
            >
              Zoom Out
            </Button>
            <Button
              startIcon={<CenterIcon />}
              onClick={handleResetZoom}
              disabled={!cfgData}
              size="small"
            >
              Reset
            </Button>
            <Button
              startIcon={<DownloadIcon />}
              onClick={downloadSVG}
              disabled={!cfgData}
              size="small"
            >
              Download
            </Button>
          </Stack>
        </Box>

        <Box mb={2}>
          <FormControl fullWidth size="small">
            <InputLabel>Select Function</InputLabel>
            <Select
              value={selectedFunction}
              onChange={handleFunctionChange}
              label="Select Function"
            >
              {availableFunctions.map((func) => (
                <MenuItem key={func} value={func}>
                  Function at {func}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {loading && (
          <Box display="flex" justifyContent="center" p={4}>
            <CircularProgress />
          </Box>
        )}

        {cfgData && (
          <Box mb={2}>
            <Stack direction="row" spacing={1}>
              <Chip 
                label={`Function: ${cfgData.function_name}`} 
                color="primary" 
                size="small" 
              />
              <Chip 
                label={`Address: ${cfgData.function_address}`} 
                color="secondary" 
                size="small" 
              />
              <Chip 
                label={`${cfgData.nodes.length} blocks`} 
                color="info" 
                size="small" 
              />
              <Chip 
                label={`${cfgData.edges.length} edges`} 
                color="success" 
                size="small" 
              />
            </Stack>
          </Box>
        )}

        <Box
          sx={{
            border: '1px solid #ddd',
            borderRadius: 1,
            overflow: 'hidden',
            backgroundColor: '#f9f9f9'
          }}
        >
          <svg
            ref={svgRef}
            width="100%"
            height="600"
            style={{ display: 'block' }}
          />
        </Box>

        {cfgData && (
          <Box mt={2}>
            <Typography variant="body2" color="text.secondary">
              <strong>Legend:</strong>{' '}
              <Chip label="Entry" size="small" sx={{ backgroundColor: '#4caf50', color: 'white', mr: 1 }} />
              <Chip label="Exit" size="small" sx={{ backgroundColor: '#f44336', color: 'white', mr: 1 }} />
              <Chip label="Conditional" size="small" sx={{ backgroundColor: '#ff9800', color: 'white', mr: 1 }} />
              <Chip label="Basic" size="small" sx={{ backgroundColor: '#2196f3', color: 'white' }} />
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default CFGVisualization; 
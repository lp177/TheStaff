import type { Host } from "@/types";

export interface FlowNode {
  id: string;
  type: string;
  position: { x: number; y: number };
  data: Record<string, unknown>;
  draggable?: boolean;
  selectable?: boolean;
  deletable?: boolean;
}

export interface FlowEdge {
  id: string;
  source: string;
  target: string;
  animated?: boolean;
  class?: string;
}

const CENTER = { x: 0, y: 0 };
const INTERNET_ID = "internet";

/** Radial hub-and-spoke: the gateway/internet sits at the centre, guests on
 *  concentric rings around it. No dagre/elk — plain trigonometry. */
export function buildGraph(hosts: Host[]): { nodes: FlowNode[]; edges: FlowEdge[] } {
  const nodes: FlowNode[] = [
    {
      id: INTERNET_ID,
      type: "internet",
      position: { ...CENTER },
      data: {},
      draggable: false,
      selectable: false, // the central hub can't be rubber-band-selected or deleted
      deletable: false,
    },
  ];
  const edges: FlowEdge[] = [];

  const count = hosts.length;
  // grow ring radius with population so cards don't overlap
  const perRing = 10;
  hosts.forEach((host, i) => {
    const ring = Math.floor(i / perRing);
    const indexInRing = i % perRing;
    const ringCount = Math.min(perRing, count - ring * perRing);
    const radius = 360 + ring * 320;
    const angle = (indexInRing / Math.max(ringCount, 1)) * 2 * Math.PI - Math.PI / 2;
    nodes.push({
      id: `host-${host.id}`,
      type: "device",
      position: {
        x: CENTER.x + radius * Math.cos(angle),
        y: CENTER.y + radius * Math.sin(angle),
      },
      data: { host },
    });
    edges.push({
      id: `edge-${host.id}`,
      source: INTERNET_ID,
      target: `host-${host.id}`,
      class: `edge-${host.worst_state}`,
    });
  });

  return { nodes, edges };
}

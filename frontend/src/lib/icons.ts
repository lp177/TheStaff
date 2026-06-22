import type { Component } from "vue";
import {
  Camera,
  Cpu,
  Gamepad2,
  Globe,
  HardDrive,
  Laptop,
  Phone,
  Printer,
  Router,
  Server,
  Smartphone,
  Tv,
} from "lucide-vue-next";

// lucide icons are functional components; type them as Vue Components so the
// typecheck doesn't depend on lucide's value-typed `Icon` export.
type LucideIcon = Component;

// device_type -> lucide icon component
const ICONS: Record<string, LucideIcon> = {
  router: Router,
  printer: Printer,
  tv_streaming: Tv,
  phone_tablet: Smartphone,
  computer: Laptop,
  nas: HardDrive,
  game_console: Gamepad2,
  ip_camera: Camera,
  voip_phone: Phone,
  iot: Cpu,
  unknown: Server,
};

export function iconFor(deviceType: string | null | undefined): LucideIcon {
  return ICONS[deviceType ?? "unknown"] ?? Server;
}

export const internetIcon = Globe;

const LABELS: Record<string, string> = {
  router: "Router / AP",
  printer: "Printer",
  tv_streaming: "Smart TV / Cast",
  phone_tablet: "Phone / Tablet",
  computer: "Computer",
  nas: "NAS / Storage",
  game_console: "Game console",
  ip_camera: "IP camera",
  voip_phone: "VoIP phone",
  iot: "IoT / Smart device",
  unknown: "Unknown device",
};

export function labelFor(deviceType: string | null | undefined): string {
  return LABELS[deviceType ?? "unknown"] ?? "Device";
}

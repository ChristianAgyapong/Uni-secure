import React, { Suspense, lazy, useState, useEffect } from "react";
import { Sidebar, ResearchTab } from "./components/Sidebar";
import { Header } from "./components/Header";
import { API } from "./api/client";
import "./index.css";

const DetectionPipelineView = lazy(() =>
  import("./components/DetectionPipelineView").then((module) => ({ default: module.DetectionPipelineView })),
);
const InterpretabilityView = lazy(() =>
  import("./components/InterpretabilityView").then((module) => ({ default: module.InterpretabilityView })),
);
const PaperBenchmarksView = lazy(() =>
  import("./components/PaperBenchmarksView").then((module) => ({ default: module.PaperBenchmarksView })),
);
const ArchitectureView = lazy(() =>
  import("./components/ArchitectureView").then((module) => ({ default: module.ArchitectureView })),
);
const SocCenterView = lazy(() =>
  import("./components/SocCenterView").then((module) => ({ default: module.SocCenterView })),
);

export function App() {
  const [currentTab, setCurrentTab] = useState<ResearchTab>("pipeline");
  const [isModelReady, setIsModelReady] = useState(false);

  useEffect(() => {
    API.health()
      .then((res) => setIsModelReady(res.model_loaded && res.trained))
      .catch(() => setIsModelReady(false));
  }, []);

  return (
    <div className="soc-shell">
      {/* ── Left Sidebar (Paper Focused) ── */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        isModelReady={isModelReady}
      />

      {/* ── Main View Area ── */}
      <div className="soc-main">
        {/* Academic Paper Header */}
        <Header />

        {/* 5 Focused Responsive Views */}
        <Suspense fallback={<div className="soc-content" role="status">Loading dashboard view...</div>}>
          {currentTab === "pipeline" && <DetectionPipelineView />}
          {currentTab === "interpretability" && <InterpretabilityView />}
          {currentTab === "benchmarks" && <PaperBenchmarksView />}
          {currentTab === "architecture" && <ArchitectureView />}
          {currentTab === "soc" && <SocCenterView />}
        </Suspense>
      </div>
    </div>
  );
}

export default App;

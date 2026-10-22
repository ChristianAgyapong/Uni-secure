import React, { useState, useEffect } from "react";
import { Sidebar, ResearchTab } from "./components/Sidebar";
import { Header } from "./components/Header";
import { DetectionPipelineView } from "./components/DetectionPipelineView";
import { InterpretabilityView } from "./components/InterpretabilityView";
import { PaperBenchmarksView } from "./components/PaperBenchmarksView";
import { ArchitectureView } from "./components/ArchitectureView";
import { SocCenterView } from "./components/SocCenterView";
import { API } from "./api/client";
import "./index.css";

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
        {currentTab === "pipeline" && <DetectionPipelineView />}
        {currentTab === "interpretability" && <InterpretabilityView />}
        {currentTab === "benchmarks" && <PaperBenchmarksView />}
        {currentTab === "architecture" && <ArchitectureView />}
        {currentTab === "soc" && <SocCenterView />}
      </div>
    </div>
  );
}

export default App;

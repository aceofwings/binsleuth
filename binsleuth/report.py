#!/usr/bin/env python

import json
from datetime import datetime

class Report:

  def __init__(self, data, build_d3js=False, build_json=False):
   
    ''' this class is used to write out a semi-self-contained html report
      yes, it writes the html to a file... yupp
      by default it does nothing but stores the data
      set flags to True to build reports on instantiation
    
      :data:  a python dictionary representing a report
    
      @TODO pull d3js packages into the environment for full self containment
    '''
    assert isinstance(data, dict), "Incorrect data format at D3Object"
    self._data = data
    self._report_time = datetime.now()
    if build_d3js: self._build_d3js()
    if build_json: self._dump_json()
    
  def _dump_json(self):
    
    ''' dump the dynamic json report
    '''
    
    with open('Report_JSON_' + str(self._report_time) + '.json', 'w') as fh:
      fh.write(json.dumps(self._data))
    
    
  def _build_d3js(self):
  
    ''' build the interactive html report
    '''
    
    with open('Report_' + str(self._report_time) + '.html', 'w') as fh:
      fh.write(
        """<!DOCTYPE html>
<meta charset="utf-8">
<style>

.node rect {
  cursor: pointer;
  fill: #fff;
  fill-opacity: 0.5;
  stroke: black;
  stroke-width: 1px;
}

.node text {
  font: 12px sans-serif;
  pointer-events: none;
  fill: black;
}

.link {
  fill: none;
  stroke: gray;
  stroke-width: 1px;
}

</style>
<body>
<script src="https://d3js.org/d3.v4.min.js"></script>
<script>

var margin = {top: 30, right: 20, bottom: 30, left: 20},
    width = 960,
    barHeight = 25,
    barWidth = (width - margin.left - margin.right) * 0.8;

var i = 0,
    duration = 400,
    root;

var diagonal = d3.linkHorizontal()
    .x(function(d) { return d.y; })
    .y(function(d) { return d.x; });

var svg = d3.select("body").append("svg")
    .attr("width", width)
  .append("g")
    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");


function moveChildren(node) {
    if(node.children) {
        node.children.forEach(function(c) { moveChildren(c); });
        node._children = node.children;
        node.children = null;
    }
}
var flare = """
      )
      fh.write(json.dumps(self._data))
      
      fh.write(
        """
root = d3.hierarchy(flare);
root.x0 = 0;
root.y0 = 0;
moveChildren(root);
update(root);


function update(source) {

  var nodes = root.descendants();

  var height = Math.max(500, nodes.length * barHeight + margin.top + margin.bottom);

  d3.select("svg").transition()
      .duration(duration)
      .attr("height", height);

  d3.select(self.frameElement).transition()
      .duration(duration)
      .style("height", height + "px");

  var index = -1;
  root.eachBefore(function(n) {
    n.x = ++index * barHeight;
    n.y = n.depth * 20;
  });

  var node = svg.selectAll(".node")
    .data(nodes, function(d) { return d.id || (d.id = ++i); });

  var nodeEnter = node.enter().append("g")
      .attr("class", "node")
      .attr("transform", function(d) { return "translate(" + source.y0 + "," + source.x0 + ")"; })
      .style("opacity", 0);

  nodeEnter.append("rect")
      .attr("y", -barHeight / 2)
      .attr("height", barHeight)
      .attr("width", barWidth)
      .style("fill", color)
      .on("click", click);

  nodeEnter.append("text")
      .attr("dy", 3.5)
      .attr("dx", 5.5)
      .text(function(d) { return d.data.name; });

  nodeEnter.transition()
      .duration(duration)
      .attr("transform", function(d) { return "translate(" + d.y + "," + d.x + ")"; })
      .style("opacity", 1);

  node.transition()
      .duration(duration)
      .attr("transform", function(d) { return "translate(" + d.y + "," + d.x + ")"; })
      .style("opacity", 1)
    .select("rect")
      .style("fill", color);

  node.exit().transition()
      .duration(duration)
      .attr("transform", function(d) { return "translate(" + source.y + "," + source.x + ")"; })
      .style("opacity", 0)
      .remove();

  var link = svg.selectAll(".link")
    .data(root.links(), function(d) { return d.target.id; });

  link.enter().insert("path", "g")
      .attr("class", "link")
      .attr("d", function(d) {
        var o = {x: source.x0, y: source.y0};
        return diagonal({source: o, target: o});
      })
    .transition()
      .duration(duration)
      .attr("d", diagonal);

  link.transition()
      .duration(duration)
      .attr("d", diagonal);

  link.exit().transition()
      .duration(duration)
      .attr("d", function(d) {
        var o = {x: source.x, y: source.y};
        return diagonal({source: o, target: o});
      })
      .remove();

  root.each(function(d) {
    d.x0 = d.x;
    d.y0 = d.y;
  });
}

function click(d) {
  if (d.children) {
    d._children = d.children;
    d.children = null;
  } else {
    d.children = d._children;
    d._children = null;
  }
  update(d);
}

function color(d) {
  return d._children ? "green" : d.children ? "#0077c8" : "tomato";
}

</script>"""
      )
      
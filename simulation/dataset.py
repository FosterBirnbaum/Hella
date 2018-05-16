import json
import argparse
import csv
import datetime
import collections

class DataGenerator():

	def __init__(self, asset_file, out_file, train, test):
		self.asset_file = asset_file
		self.out_file = out_file
		self.train = train
		self.test = test

		raw_asset = self.read_asset_file(self.asset_file)
		self.data_points = self.process_asset(raw_asset)
		self.config = self.read_config_file()

	def read_asset_file(self, in_file):
		"""
		parse asset from asset file
		return raw parse of asset
		"""
		asset = []
		with open(in_file, 'r') as asset_file:
			reader = csv.DictReader(asset_file)
			for row in reader:
				asset.append([float(row[key]) for key in ['TIME', 'LATITUDE','LONGITUDE']])
		return asset

	def process_asset(self, asset):
		"""
		add seconds granularity to asset
		add interpolated data points to asset
		return new asset
		"""
		asset = self.granular_asset(asset)
		asset = self.interpolated_asset(asset)
		return asset

	def granular_asset(self, asset):
		"""
		add seconds granularity to asset
		return granular asset
		"""
		granular_asset = []
		time_buckets = collections.defaultdict(list)

		for time, lat, lon in asset:
			time_buckets[time].append((time, lat, lon))

		for time_key in sorted(time_buckets.keys()):
			per_minute = len(time_buckets[time_key])
			seconds_per = 60 // per_minute

			for dp_i, data_point in enumerate(time_buckets[time]):
				time, lat, lon = data_point
				granular_asset.append((time + dp_i * seconds_per, lat, lon))

		return granular_asset	

	def interpolated_asset(self, asset):
		"""
		add interpolated data points to asset
		return interpolated asset
		"""
		interpolated_asset = []

		for dp_i in range(len(asset) - 1):
			curr_dp = asset[dp_i]
			next_dp = asset[dp_i + 1]

			between_asset = []
			start_time, start_lat, start_lon = curr_dp
			end_time, end_lat, end_lon = next_dp

			seconds_delta = int(end_time - start_time)
			lat_delta = end_lat - start_lat
			lon_delta = end_lon - start_lon

			time_increment = 1
			lat_increment = lat_delta / seconds_delta
			lon_increment = lon_delta / seconds_delta

			for s_i in range(seconds_delta):
				between_time = start_time + s_i * time_increment
				between_lat = start_lat + s_i * lat_increment
				between_lon = start_lon + s_i * lon_increment
				between_asset.append((between_time, between_lat, between_lon))

			interpolated_asset.extend(between_asset)

		return interpolated_asset

	def read_config_file(self, in_file='dataset_gen_config.json'):
		"""
		read in the probabilistic configuration parameters
		return the config dictionary 
		"""
		with open(in_file, 'r') as jsonfile:
			config = json.load(jsonfile)
		return config

	def build_dataset(self):

		seconds_passed = 0

		for time, lat, lon in self.data_points:
			now_datetime = datetime.datetime.fromtimestamp(time)

			is_weekday = now_datetime.weekday() < 5
			is_dawn = now_datetime.hour >= 0 and now_datetime.hour < 6
			is_morning = now_datetime.hour >= 6 and now_datetime.hour < 12
			is_afternoon = now_datetime.hour >= 12 and now_datetime.hour < 18
			is_evening = now_datetime.hour >= 18 and now_datetime.hour < 24

			do_elevation = seconds_passed % self.config['elevation']['frequency'] == 0
			do_places	 = seconds_passed % self.config['places_nearby']['frequency'] == 0
			do_location	 = seconds_passed % self.config['location_info']['frequency'] == 0
			do_weather	 = seconds_passed % self.config['weather']['frequency'] == 0
			do_news		 = seconds_passed % self.config['news']['frequency'] == 0

if __name__ == '__main__':

	parser = argparse.ArgumentParser()

	parser.add_argument('asset_file', help='the asset file path')
	parser.add_argument('out_file', help='the packet data path')

	train_test = parser.add_mutually_exclusive_group(required=True)
	train_test.add_argument('--train', action='store_true', default=False)
	train_test.add_argument('--test', action='store_true', default=False)

	args = parser.parse_args()
	
	data_generator = DataGenerator(args.asset_file, args.out_file, args.train, args.test)
	data_generator.build_dataset()